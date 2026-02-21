package inbound

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	gonet "net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport/internet/stat"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"google.golang.org/protobuf/proto"
)

const (
	ReflexMagic         uint32 = 0x5246584C // "RFXL"
	ReflexMinPeekSize          = 64
	MaxPolicyReqLen            = 4096
	AllowedClockSkewSec int64  = 300
)

type Handler struct {
	clients      []*protocol.MemoryUser
	userPolicies map[string]string
	fallback     *FallbackConfig
	nonceMu      sync.Mutex
	nonces       map[string]int64
}

type MemoryAccount struct {
	Id string
}

func (a *MemoryAccount) Equals(account protocol.Account) bool {
	reflexAccount, ok := account.(*MemoryAccount)
	if !ok {
		return false
	}
	return a.Id == reflexAccount.Id
}

func (a *MemoryAccount) ToProto() proto.Message {
	return &reflex.Account{
		Id: a.Id,
	}
}

type FallbackConfig struct {
	Dest uint32
}

type ClientHandshake struct {
	PublicKey [32]byte
	UserID    [16]byte
	PolicyReq []byte
	Timestamp int64
	Nonce     [16]byte
}

type ServerHandshake struct {
	PublicKey   [32]byte
	PolicyGrant []byte
}

func (h *Handler) Network() []net.Network {
	return []net.Network{net.Network_TCP}
}

func (h *Handler) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	if network != net.Network_TCP {
		return h.handleFallbackDeny(conn)
	}

	reader := bufio.NewReader(conn)

	peeked, err := reader.Peek(ReflexMinPeekSize)
	if err != nil && !errors.Is(err, bufio.ErrBufferFull) && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return err
	}

	if h.isReflexHandshake(peeked) {
		if h.isReflexMagic(peeked) {
			return h.handleReflexMagic(ctx, reader, conn, dispatcher)
		}
		if h.isHTTPPostLike(peeked) {
			return h.handleReflexHTTP(ctx, reader, conn, dispatcher)
		}
	}

	return h.handleFallback(ctx, reader, conn)
}

func init() {
	common.Must(common.RegisterConfig((*reflex.InboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*reflex.InboundConfig))
	}))
}

func New(_ context.Context, config *reflex.InboundConfig) (proxy.Inbound, error) {
	handler := &Handler{
		clients:      make([]*protocol.MemoryUser, 0),
		userPolicies: make(map[string]string),
		nonces:       make(map[string]int64),
	}

	for _, client := range config.Clients {
		handler.clients = append(handler.clients, &protocol.MemoryUser{
			Email:   client.Id,
			Account: &MemoryAccount{Id: client.Id},
		})
		if client.Policy != "" {
			handler.userPolicies[client.Id] = client.Policy
		}
	}

	if config.Fallback != nil {
		handler.fallback = &FallbackConfig{
			Dest: config.Fallback.Dest,
		}
	}

	return handler, nil
}

func (h *Handler) handleReflexMagic(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher) error {
	magic := make([]byte, 4)
	if _, err := io.ReadFull(reader, magic); err != nil {
		return err
	}

	hs, err := ReadClientHandshake(reader)
	if err != nil {
		return h.handleFallback(ctx, reader, conn)
	}
	return h.processHandshake(ctx, reader, conn, dispatcher, hs)
}

func (h *Handler) handleReflexHTTP(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher) error {
	req, err := http.ReadRequest(reader)
	if err != nil {
		return h.handleFallback(ctx, reader, conn)
	}
	defer func() { _ = req.Body.Close() }()

	if req.Method != http.MethodPost {
		return h.handleFallback(ctx, reader, conn)
	}

	var body struct {
		Data string `json:"data"`
	}
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		return h.handleFallback(ctx, reader, conn)
	}

	raw, err := base64.StdEncoding.DecodeString(body.Data)
	if err != nil {
		return h.handleFallback(ctx, reader, conn)
	}

	hs, err := ParseClientHandshakeBytes(raw)
	if err != nil {
		return h.handleFallback(ctx, reader, conn)
	}

	return h.processHandshake(ctx, reader, conn, dispatcher, hs)
}

func (h *Handler) processHandshake(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, clientHS ClientHandshake) error {
	if err := ValidateTimestamp(clientHS.Timestamp); err != nil {
		return h.handleFallback(ctx, reader, conn)
	}

	user, err := h.authenticateUser(clientHS.UserID)
	if err != nil {
		return h.handleFallback(ctx, reader, conn)
	}

	if err := h.checkReplay(user, clientHS.Nonce, clientHS.Timestamp); err != nil {
		return h.handleFallback(ctx, reader, conn)
	}

	serverPrivateKey, serverPublicKey, err := GenerateKeyPair()
	if err != nil {
		return err
	}
	sharedKey, err := DeriveSharedKey(serverPrivateKey, clientHS.PublicKey)
	if err != nil {
		return h.handleFallback(ctx, reader, conn)
	}
	sessionKey := DeriveSessionKey(sharedKey, clientHS.Nonce[:])

	serverHS := ServerHandshake{
		PublicKey:   serverPublicKey,
		PolicyGrant: EncryptPolicyGrant(user, sessionKey),
	}

	if _, err := conn.Write(FormatHTTPResponse(serverHS)); err != nil {
		return err
	}

	return h.handleSession(ctx, reader, conn, dispatcher, sessionKey, user)
}

func (h *Handler) authenticateUser(userID [16]byte) (*protocol.MemoryUser, error) {
	for _, user := range h.clients {
		account, ok := user.Account.(*MemoryAccount)
		if !ok {
			continue
		}

		accountID, err := uuid.ParseString(account.Id)
		if err != nil {
			continue
		}

		if subtle.ConstantTimeCompare(accountID[:], userID[:]) == 1 {
			return user, nil
		}
	}
	return nil, errors.New("user not found")
}

func (h *Handler) checkReplay(user *protocol.MemoryUser, nonce [16]byte, ts int64) error {
	key := user.Email + ":" + hex.EncodeToString(nonce[:])

	h.nonceMu.Lock()
	defer h.nonceMu.Unlock()

	now := time.Now().Unix()
	// keep recent nonce
	for k, seenAt := range h.nonces {
		if now-seenAt > AllowedClockSkewSec*2 {
			delete(h.nonces, k)
		}
	}

	if _, found := h.nonces[key]; found {
		return errors.New("nonce already seen, request rejected")
	}
	h.nonces[key] = ts
	return nil
}

func (h *Handler) handleSession(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, sessionKey []byte, user *protocol.MemoryUser) error {
	session, err := NewSession(sessionKey)
	if err != nil {
		return err
	}
	session.SetTrafficProfile(GetTrafficProfile(h.getUserPolicy(user)))

	for {
		frame, err := session.ReadFrame(reader)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			return err
		}

		switch frame.Type {
		case FrameTypeData:
			if err := h.handleData(ctx, frame.Payload, conn, dispatcher, session, user); err != nil {
				return err
			}
		case FrameTypePadding:
			session.HandleControlFrame(frame)
			continue
		case FrameTypeTiming:
			session.HandleControlFrame(frame)
			continue
		case FrameTypeClose:
			return nil
		default:
			return errors.New("unknown frame type")
		}
	}
}

func (h *Handler) isHTTPPostLike(peeked []byte) bool {
	prefix := strings.ToUpper(string(peeked))
	return strings.HasPrefix(prefix, "POST ")
}

func (h *Handler) isReflexMagic(data []byte) bool {
	// the first 4 are "magic"
	if len(data) < 4 {
		return false
	}
	return binary.BigEndian.Uint32(data[:4]) == ReflexMagic
}

func (h *Handler) isReflexHandshake(data []byte) bool {
	return h.isReflexMagic(data) || h.isHTTPPostLike(data)
}

func (h *Handler) handleFallbackDeny(conn stat.Connection) error {
	resp := []byte("HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: 9\r\nConnection: close\r\n\r\nForbidden")
	_, _ = conn.Write(resp)
	return nil
}

func (h *Handler) handleFallback(ctx context.Context, reader *bufio.Reader, conn stat.Connection) error {
	if h.fallback == nil || h.fallback.Dest == 0 {
		return h.handleFallbackDeny(conn)
	}

	target, err := (&gonet.Dialer{}).DialContext(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", h.fallback.Dest))
	if err != nil {
		return err
	}
	defer func() { _ = target.Close() }()

	wrapped := &preloadedConn{
		Reader:     reader,
		Connection: conn,
	}

	copyDone := make(chan error, 2)
	go func() {
		_, err := io.Copy(target, wrapped)
		copyDone <- err
	}()
	go func() {
		_, err := io.Copy(wrapped, target)
		copyDone <- err
	}()

	err1 := <-copyDone
	err2 := <-copyDone
	if err1 != nil && !errors.Is(err1, io.EOF) {
		return err1
	}
	if err2 != nil && !errors.Is(err2, io.EOF) {
		return err2
	}
	return nil
}

type preloadedConn struct {
	*bufio.Reader
	stat.Connection
}

func (pc *preloadedConn) Read(b []byte) (int, error) {
	return pc.Reader.Read(b)
}

func (h *Handler) handleData(ctx context.Context, data []byte, conn stat.Connection, dispatcher routing.Dispatcher, session *Session, _ *protocol.MemoryUser) error {
	dest, payload, err := ParseDestinationAndPayload(data)
	if err != nil {
		return err
	}

	link, err := dispatcher.Dispatch(ctx, dest)
	if err != nil {
		return err
	}

	if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(payload)}); err != nil {
		return err
	}

	go func() {
		for {
			mb, err := link.Reader.ReadMultiBuffer()
			if err != nil {
				return
			}
			for _, b := range mb {
				if b == nil {
					continue
				}
				if err := session.WriteFrameWithMorphing(
					conn, FrameTypeData, b.Bytes()); err != nil {
					b.Release()
					return
				}
				b.Release()
			}
		}
	}()

	return nil
}

func (h *Handler) getUserPolicy(user *protocol.MemoryUser) string {
	if user == nil {
		return DefaultProfile.Name
	}
	if p, ok := h.userPolicies[user.Email]; ok && p != "" {
		return p
	}
	return DefaultProfile.Name
}

func ParseDestinationAndPayload(data []byte) (net.Destination, []byte, error) {
	// the minimum possible length is 4
	if len(data) < 4 {
		return net.Destination{}, nil, errors.New("invalid data frame payload")
	}

	addrLen := int(data[0])
	if addrLen == 0 || len(data) < 1+addrLen+2 {
		return net.Destination{}, nil, errors.New("invalid destination in payload")
	}

	address := net.ParseAddress(string(data[1 : 1+addrLen]))
	port := binary.BigEndian.Uint16(data[1+addrLen : 1+addrLen+2])
	payload := data[1+addrLen+2:]

	dest := net.TCPDestination(address, net.Port(port))
	return dest, payload, nil
}

func ReadClientHandshake(r io.Reader) (ClientHandshake, error) {
	var hs ClientHandshake
	if _, err := io.ReadFull(r, hs.PublicKey[:]); err != nil {
		return hs, err
	}
	if _, err := io.ReadFull(r, hs.UserID[:]); err != nil {
		return hs, err
	}
	var ts [8]byte
	if _, err := io.ReadFull(r, ts[:]); err != nil {
		return hs, err
	}
	hs.Timestamp = int64(binary.BigEndian.Uint64(ts[:]))
	if _, err := io.ReadFull(r, hs.Nonce[:]); err != nil {
		return hs, err
	}
	var policyLen [2]byte
	if _, err := io.ReadFull(r, policyLen[:]); err != nil {
		return hs, err
	}
	len := int(binary.BigEndian.Uint16(policyLen[:]))
	if len > MaxPolicyReqLen {
		return hs, errors.New("policy request too large")
	}
	hs.PolicyReq = make([]byte, len)
	if _, err := io.ReadFull(r, hs.PolicyReq); err != nil {
		return hs, err
	}
	return hs, nil
}

func ParseClientHandshakeBytes(raw []byte) (ClientHandshake, error) {
	return ReadClientHandshake(bytes.NewReader(raw))
}

func GenerateKeyPair() ([32]byte, [32]byte, error) {
	var privateKey [32]byte
	var publicKey [32]byte
	if _, err := rand.Read(privateKey[:]); err != nil {
		return privateKey, publicKey, err
	}

	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	curve25519.ScalarBaseMult(&publicKey, &privateKey)
	return privateKey, publicKey, nil
}

// curve25519.ScalarMult is deprecated
func DeriveSharedKey(privateKey, peerPublicKey [32]byte) ([32]byte, error) {
	var shared [32]byte
	key, err := curve25519.X25519(privateKey[:], peerPublicKey[:])
	if err != nil {
		return shared, err
	}
	copy(shared[:], key)
	return shared, nil
}

func DeriveSessionKey(sharedKey [32]byte, salt []byte) []byte {
	r := hkdf.New(sha256.New, sharedKey[:], salt, []byte("reflex-session"))
	sessionKey := make([]byte, 32)
	_, _ = io.ReadFull(r, sessionKey)
	return sessionKey
}

func ValidateTimestamp(ts int64) error {
	now := time.Now().Unix()
	if ts > now+AllowedClockSkewSec || ts < now-AllowedClockSkewSec {
		return errors.New("timestamp is out of allowed range")
	}
	return nil
}

func EncryptPolicyGrant(user *protocol.MemoryUser, sessionKey []byte) []byte {
	plain := []byte(user.Email)
	out := make([]byte, len(plain))
	for i := range plain {
		out[i] = plain[i] ^ sessionKey[i%len(sessionKey)]
	}
	return out
}

func FormatHTTPResponse(hs ServerHandshake) []byte {
	payload := map[string]string{
		"publicKey":   base64.StdEncoding.EncodeToString(hs.PublicKey[:]),
		"policyGrant": base64.StdEncoding.EncodeToString(hs.PolicyGrant),
		"status":      "ok",
	}
	b, _ := json.Marshal(payload)
	header := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
	header += strconv.Itoa(len(b))
	header += "\r\nConnection: keep-alive\r\n\r\n"
	return append([]byte(header), b...)
}
