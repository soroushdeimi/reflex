package inbound

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	stdnet "net"
	"net/http"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/stat"
)

const (
	ReflexMagic            uint32 = 0x5246584C // REFX
	reflexMinHandshakeSize        = 64
	maxPolicyPayloadSize          = 4096
	handshakeSkew                 = 5 * time.Minute
	defaultNonceLifetime          = 15 * time.Minute
)

// ClientHandshake is the parsed handshake payload from the client.
type ClientHandshake struct {
	PublicKey [32]byte
	UserID    [16]byte
	PolicyReq []byte
	Timestamp int64
	Nonce     [16]byte
}

// ServerHandshake is the handshake payload sent by the server.
type ServerHandshake struct {
	PublicKey   [32]byte
	PolicyGrant []byte
}

type handshakeHTTPEnvelope struct {
	Data string `json:"data"`
}

type preloadedConn struct {
	*bufio.Reader
	stat.Connection
}

func (p *preloadedConn) Read(b []byte) (int, error) {
	return p.Reader.Read(b)
}

func peekForDetection(reader *bufio.Reader, n int) ([]byte, error) {
	peeked, err := reader.Peek(n)
	if err == nil {
		return peeked, nil
	}
	if err == bufio.ErrBufferFull || err == io.EOF {
		available := reader.Buffered()
		if available == 0 {
			return nil, err
		}
		return reader.Peek(available)
	}
	return nil, err
}

func (h *Handler) isReflexMagic(data []byte) bool {
	return len(data) >= 4 && binary.BigEndian.Uint32(data[:4]) == ReflexMagic
}

func (h *Handler) isHTTPPostLike(data []byte) bool {
	return len(data) >= 5 && string(data[:5]) == "POST "
}

func (h *Handler) isReflexHandshake(data []byte) bool {
	if h.isReflexMagic(data) {
		return true
	}
	return h.isHTTPPostLike(data)
}

func (h *Handler) handleReflexMagic(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher) error {
	var magic [4]byte
	if _, err := io.ReadFull(reader, magic[:]); err != nil {
		return err
	}
	if binary.BigEndian.Uint32(magic[:]) != ReflexMagic {
		return h.handleFallback(ctx, reader, conn)
	}

	clientHS, err := readBinaryHandshake(reader)
	if err != nil {
		return h.handleFallback(ctx, reader, conn)
	}
	return h.processHandshake(ctx, reader, conn, dispatcher, clientHS)
}

func (h *Handler) handleReflexHTTP(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher) error {
	req, err := http.ReadRequest(reader)
	if err != nil {
		return h.handleFallback(ctx, reader, conn)
	}
	defer req.Body.Close()

	if req.Method != http.MethodPost {
		return h.handleFallback(ctx, reader, conn)
	}

	body, err := io.ReadAll(io.LimitReader(req.Body, maxPolicyPayloadSize))
	if err != nil {
		return h.handleFallback(ctx, reader, conn)
	}
	var envelope handshakeHTTPEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		return h.handleFallback(ctx, reader, conn)
	}

	rawPayload, err := base64.StdEncoding.DecodeString(envelope.Data)
	if err != nil {
		return h.handleFallback(ctx, reader, conn)
	}
	if len(rawPayload) >= 4 && binary.BigEndian.Uint32(rawPayload[:4]) == ReflexMagic {
		rawPayload = rawPayload[4:]
	}

	clientHS, err := parseBinaryHandshake(rawPayload)
	if err != nil {
		return h.handleFallback(ctx, reader, conn)
	}
	return h.processHandshake(ctx, reader, conn, dispatcher, clientHS)
}

func readBinaryHandshake(r io.Reader) (ClientHandshake, error) {
	var head [32 + 16 + 8 + 16 + 2]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return ClientHandshake{}, err
	}

	var hs ClientHandshake
	copy(hs.PublicKey[:], head[0:32])
	copy(hs.UserID[:], head[32:48])
	hs.Timestamp = int64(binary.BigEndian.Uint64(head[48:56]))
	copy(hs.Nonce[:], head[56:72])
	policyLen := binary.BigEndian.Uint16(head[72:74])

	if policyLen > maxPolicyPayloadSize {
		return ClientHandshake{}, errors.New("reflex handshake policy too large")
	}
	if policyLen > 0 {
		hs.PolicyReq = make([]byte, policyLen)
		if _, err := io.ReadFull(r, hs.PolicyReq); err != nil {
			return ClientHandshake{}, err
		}
	}
	return hs, nil
}

func parseBinaryHandshake(raw []byte) (ClientHandshake, error) {
	if len(raw) < 74 {
		return ClientHandshake{}, errors.New("reflex handshake too short")
	}
	policyLen := int(binary.BigEndian.Uint16(raw[72:74]))
	if policyLen > maxPolicyPayloadSize {
		return ClientHandshake{}, errors.New("reflex handshake policy too large")
	}
	if len(raw) != 74+policyLen {
		return ClientHandshake{}, errors.New("reflex handshake malformed payload length")
	}
	var hs ClientHandshake
	copy(hs.PublicKey[:], raw[0:32])
	copy(hs.UserID[:], raw[32:48])
	hs.Timestamp = int64(binary.BigEndian.Uint64(raw[48:56]))
	copy(hs.Nonce[:], raw[56:72])
	if policyLen > 0 {
		hs.PolicyReq = append([]byte(nil), raw[74:]...)
	}
	return hs, nil
}

func (h *Handler) processHandshake(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, clientHS ClientHandshake) error {
	if err := validateHandshakeTimestamp(clientHS.Timestamp); err != nil {
		_ = writeHTTPError(conn, http.StatusForbidden)
		return h.handleFallback(ctx, reader, conn)
	}
	if !h.checkAndStoreNonce(clientHS.Nonce) {
		_ = writeHTTPError(conn, http.StatusForbidden)
		return h.handleFallback(ctx, reader, conn)
	}

	serverPriv, serverPub, err := generateKeyPair()
	if err != nil {
		_ = writeHTTPError(conn, http.StatusInternalServerError)
		return err
	}
	sharedKey, err := deriveSharedKey(serverPriv, clientHS.PublicKey)
	if err != nil {
		_ = writeHTTPError(conn, http.StatusForbidden)
		return h.handleFallback(ctx, reader, conn)
	}
	sessionKey, err := deriveSessionKey(sharedKey[:], clientHS.Nonce[:])
	if err != nil {
		_ = writeHTTPError(conn, http.StatusInternalServerError)
		return err
	}

	user, err := h.authenticateUser(clientHS.UserID)
	if err != nil {
		_ = writeHTTPError(conn, http.StatusForbidden)
		return h.handleFallback(ctx, reader, conn)
	}

	grant, err := encryptPolicyGrant(sessionKey, userPolicy(user))
	if err != nil {
		_ = writeHTTPError(conn, http.StatusInternalServerError)
		return err
	}

	serverHS := ServerHandshake{PublicKey: serverPub, PolicyGrant: grant}
	if err := writeHandshakeResponse(conn, serverHS); err != nil {
		return err
	}

	return h.handleSession(ctx, reader, conn, dispatcher, sessionKey, user)
}

func validateHandshakeTimestamp(ts int64) error {
	t := time.Unix(ts, 0)
	now := time.Now()
	if t.Before(now.Add(-handshakeSkew)) || t.After(now.Add(handshakeSkew)) {
		return errors.New("reflex handshake timestamp out of range")
	}
	return nil
}

func generateKeyPair() ([]byte, [32]byte, error) {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, [32]byte{}, err
	}
	pub := privateKey.PublicKey().Bytes()
	var publicKey [32]byte
	copy(publicKey[:], pub)
	return privateKey.Bytes(), publicKey, nil
}

func deriveSharedKey(privateKey []byte, peerPublic [32]byte) ([32]byte, error) {
	// X25519 is the Montgomery form of Curve25519 used for ECDH key agreement.
	priv, err := ecdh.X25519().NewPrivateKey(privateKey)
	if err != nil {
		return [32]byte{}, err
	}
	peer, err := ecdh.X25519().NewPublicKey(peerPublic[:])
	if err != nil {
		return [32]byte{}, err
	}
	secret, err := priv.ECDH(peer)
	if err != nil {
		return [32]byte{}, err
	}
	var shared [32]byte
	copy(shared[:], secret)
	return shared, nil
}

func deriveSessionKey(sharedKey, salt []byte) ([]byte, error) {
	r := hkdf.New(sha256.New, sharedKey, salt, []byte("reflex-session"))
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}

func (h *Handler) authenticateUser(userID [16]byte) (*protocol.MemoryUser, error) {
	uid, err := uuid.ParseBytes(userID[:])
	if err != nil {
		return nil, err
	}
	uidStr := uid.String()
	for _, user := range h.clients {
		account, ok := user.Account.(*MemoryAccount)
		if !ok {
			continue
		}
		if account.ID == uidStr {
			return user, nil
		}
	}
	return nil, errors.New("reflex user not found")
}

func userPolicy(user *protocol.MemoryUser) string {
	if user == nil {
		return ""
	}
	if account, ok := user.Account.(*MemoryAccount); ok {
		return account.Policy
	}
	return ""
}

func encryptPolicyGrant(sessionKey []byte, policy string) ([]byte, error) {
	aead, err := chacha20poly1305.New(sessionKey)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := aead.Seal(nil, nonce, []byte(policy), nil)
	return append(nonce, ciphertext...), nil
}

func marshalServerHandshake(hs ServerHandshake) []byte {
	policyLen := len(hs.PolicyGrant)
	payload := make([]byte, 32+2+policyLen)
	copy(payload[:32], hs.PublicKey[:])
	binary.BigEndian.PutUint16(payload[32:34], uint16(policyLen))
	copy(payload[34:], hs.PolicyGrant)
	return payload
}

func writeHandshakeResponse(w io.Writer, hs ServerHandshake) error {
	encoded := base64.StdEncoding.EncodeToString(marshalServerHandshake(hs))
	body, err := json.Marshal(handshakeHTTPEnvelope{Data: encoded})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: keep-alive\r\n\r\n%s", len(body), body)
	return err
}

func writeHTTPError(w io.Writer, status int) error {
	text := http.StatusText(status)
	if text == "" {
		text = "Error"
	}
	body := []byte(text)
	_, err := fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", status, text, len(body), body)
	return err
}

func (h *Handler) checkAndStoreNonce(nonce [16]byte) bool {
	h.nonceMu.Lock()
	defer h.nonceMu.Unlock()

	now := time.Now().Unix()
	h.cleanupExpiredNonces(now)
	if _, ok := h.seenNonces[nonce]; ok {
		return false
	}
	h.seenNonces[nonce] = now
	return true
}

func (h *Handler) cleanupExpiredNonces(now int64) {
	for nonce, ts := range h.seenNonces {
		if now-ts > int64(h.nonceLifetime/time.Second) {
			delete(h.seenNonces, nonce)
		}
	}
}

func (h *Handler) handleFallback(ctx context.Context, reader *bufio.Reader, conn stat.Connection) error {
	_ = ctx
	if h.fallback == nil || h.fallback.Dest == 0 {
		return errors.New("reflex handshake not matched and fallback is not configured")
	}
	target, err := stdnet.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", h.fallback.Dest))
	if err != nil {
		return err
	}
	defer target.Close()

	wrapped := &preloadedConn{
		Reader:     reader,
		Connection: conn,
	}

	errCh := make(chan error, 2)
	go func() {
		_, e := io.Copy(target, wrapped)
		errCh <- e
	}()
	go func() {
		_, e := io.Copy(wrapped, target)
		errCh <- e
	}()

	err = <-errCh
	if err == nil || errors.Cause(err) == io.EOF {
		return nil
	}
	return err
}
