package inbound

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	stdnet "net"
	"strconv"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"google.golang.org/protobuf/proto"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/features/routing"
)

// ReflexMagic is the magic number ("REFX") used for fast handshake detection.
const ReflexMagic uint32 = 0x5246584C

// ReflexMinHandshakeSize is the minimum number of bytes we peek to decide protocol.
const ReflexMinHandshakeSize = 64

type Handler struct {
	clients        []*protocol.MemoryUser
	fallback       *FallbackConfig
	defaultProfile *reflex.TrafficProfile
}

// MemoryAccount implements protocol.Account for Reflex.
type MemoryAccount struct {
	Id string
}

// Equals implements protocol.Account.
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

// ClientHandshake carries client-side handshake data.
type ClientHandshake struct {
	PublicKey [32]byte
	UserID    [16]byte
	PolicyReq []byte
	Timestamp int64
	Nonce     [16]byte
}

// ClientHandshakePacket is the full binary packet on the wire.
// Layout (big endian):
//   magic(4) | pub(32) | user(16) | ts(8) | nonce(16) | policyLen(2) | policyReq
type ClientHandshakePacket struct {
	Handshake ClientHandshake
}

// ServerHandshake is the response sent back to the client.
type ServerHandshake struct {
	PublicKey   [32]byte `json:"public_key"`
	PolicyGrant []byte   `json:"policy_grant"`
}

func (h *Handler) Network() []net.Network {
	return []net.Network{net.Network_TCP}
}

// Process performs handshake detection, authentication, and then either handles
// Reflex traffic or falls back to a normal web server.
func (h *Handler) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	reader := bufio.NewReader(conn)

	peeked, err := reader.Peek(ReflexMinHandshakeSize)
	if err != nil {
		if err == io.EOF {
			return nil
		}
		return err
	}

	// Decide whether this is Reflex traffic.
	if isReflexHandshake(peeked) {
		// Prefer magic (fast), then HTTP POST-like.
		if len(peeked) >= 4 {
			magic := binary.BigEndian.Uint32(peeked[0:4])
			if magic == ReflexMagic {
				return h.handleReflexMagic(ctx, reader, conn, dispatcher)
			}
		}
		if isHTTPPostLike(peeked) {
			return h.handleReflexHTTP(ctx, reader, conn, dispatcher)
		}
		// If detection said Reflex but we can't parse, treat as fallback.
		return h.handleFallback(ctx, reader, conn)
	}

	// Not Reflex, forward to fallback web server.
	return h.handleFallback(ctx, reader, conn)
}

func init() {
	common.Must(common.RegisterConfig((*reflex.InboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*reflex.InboundConfig))
	}))
}

func New(ctx context.Context, config *reflex.InboundConfig) (proxy.Inbound, error) {
	handler := &Handler{
		clients: make([]*protocol.MemoryUser, 0),
	}

	for _, client := range config.Clients {
		handler.clients = append(handler.clients, &protocol.MemoryUser{
			Email: client.Id,
			Account: &MemoryAccount{
				Id: client.Id,
			},
		})
	}

	if config.Fallback != nil {
		handler.fallback = &FallbackConfig{
			Dest: config.Fallback.Dest,
		}
	}
	if p := reflex.Profiles["http2-api"]; p != nil {
		handler.defaultProfile = p
	}

	return handler, nil
}

// isReflexHandshake combines magic-number and HTTP POST-like detection.
func isReflexHandshake(data []byte) bool {
	if isReflexMagic(data) {
		return true
	}
	if isHTTPPostLike(data) {
		return true
	}
	return false
}

// isReflexMagic checks the leading magic number.
func isReflexMagic(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	magic := binary.BigEndian.Uint32(data[0:4])
	return magic == ReflexMagic
}

// isHTTPPostLike checks whether the first bytes look like an HTTP POST request.
func isHTTPPostLike(peeked []byte) bool {
	if len(peeked) < 14 {
		return false
	}
	// "POST " ... "HTTP/1.1"
	if string(peeked[0:4]) != "POST" {
		return false
	}
	if !containsHTTPVersion(peeked) {
		return false
	}
	return true
}

func containsHTTPVersion(b []byte) bool {
	for i := 0; i+8 <= len(b); i++ {
		if string(b[i:i+8]) == "HTTP/1.1" {
			return true
		}
	}
	return false
}

func (h *Handler) handleReflexMagic(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher) error {
	// Consume magic.
	magicBuf := make([]byte, 4)
	if _, err := io.ReadFull(reader, magicBuf); err != nil {
		return err
	}

	// Read fixed part.
	fixedSize := 32 + 16 + 8 + 16 + 2 // pub + user + ts + nonce + policyLen
	fixed := make([]byte, fixedSize)
	if _, err := io.ReadFull(reader, fixed); err != nil {
		return err
	}

	offset := 0
	var hs ClientHandshake
	copy(hs.PublicKey[:], fixed[offset:offset+32])
	offset += 32
	copy(hs.UserID[:], fixed[offset:offset+16])
	offset += 16
	hs.Timestamp = int64(binary.BigEndian.Uint64(fixed[offset : offset+8]))
	offset += 8
	copy(hs.Nonce[:], fixed[offset:offset+16])
	offset += 16
	policyLen := int(binary.BigEndian.Uint16(fixed[offset : offset+2]))

	if policyLen > 0 {
		hs.PolicyReq = make([]byte, policyLen)
		if _, err := io.ReadFull(reader, hs.PolicyReq); err != nil {
			return err
		}
	}

	return h.processHandshake(ctx, reader, conn, dispatcher, hs)
}

func (h *Handler) handleReflexHTTP(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher) error {
	// Simple HTTP request parsing (enough for our POST / JSON body).
	// Read request line and headers.
	var contentLength int
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		if line == "\r\n" {
			break
		}
		// Very small header parser for Content-Length.
		if len(line) >= 16 && (line[0:15] == "Content-Length" || line[0:15] == "content-length") {
			// naive parse: "Content-Length: "
			for i := 0; i < len(line); i++ {
				if line[i] >= '0' && line[i] <= '9' {
					var v int
					for ; i < len(line) && line[i] >= '0' && line[i] <= '9'; i++ {
						v = v*10 + int(line[i]-'0')
					}
					contentLength = v
					break
				}
			}
		}
	}

	if contentLength <= 0 {
		return errors.New("invalid content length")
	}

	body := make([]byte, contentLength)
	if _, err := io.ReadFull(reader, body); err != nil {
		return err
	}

	var payload struct {
		Data string `json:"data"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return err
	}

	raw, err := base64.StdEncoding.DecodeString(payload.Data)
	if err != nil {
		return err
	}

	hs, err := parseClientHandshakeFromBytes(raw)
	if err != nil {
		return err
	}

	return h.processHandshake(ctx, reader, conn, dispatcher, hs)
}

func parseClientHandshakeFromBytes(b []byte) (ClientHandshake, error) {
	var hs ClientHandshake
	if len(b) < 32+16+8+16 {
		return hs, errors.New("handshake packet too short")
	}
	offset := 0
	copy(hs.PublicKey[:], b[offset:offset+32])
	offset += 32
	copy(hs.UserID[:], b[offset:offset+16])
	offset += 16
	hs.Timestamp = int64(binary.BigEndian.Uint64(b[offset : offset+8]))
	offset += 8
	copy(hs.Nonce[:], b[offset:offset+16])
	offset += 16
	if offset < len(b) {
		hs.PolicyReq = make([]byte, len(b)-offset)
		copy(hs.PolicyReq, b[offset:])
	}
	return hs, nil
}

func generateKeyPair() (priv [32]byte, pub [32]byte, err error) {
	if _, err = io.ReadFull(rand.Reader, priv[:]); err != nil {
		return
	}
	curve25519.ScalarBaseMult(&pub, &priv)
	return
}

func deriveSharedKey(privateKey, peerPublicKey [32]byte) [32]byte {
	var shared [32]byte
	curve25519.ScalarMult(&shared, &privateKey, &peerPublicKey)
	return shared
}

func deriveSessionKey(sharedKey [32]byte, salt []byte) []byte {
	h := hkdf.New(sha256.New, sharedKey[:], salt, []byte("reflex-session"))
	sessionKey := make([]byte, 32)
	_, _ = io.ReadFull(h, sessionKey)
	return sessionKey
}

func (h *Handler) authenticateUser(userID [16]byte) (*protocol.MemoryUser, error) {
	userIDStr := uuid.UUID(userID).String()
	for _, user := range h.clients {
		if acc, ok := user.Account.(*MemoryAccount); ok && acc.Id == userIDStr {
			return user, nil
		}
	}
	return nil, errors.New("user not found")
}

func (h *Handler) processHandshake(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, clientHS ClientHandshake) error {
	// Basic timestamp check to avoid trivial replay.
	now := time.Now().Unix()
	if clientHS.Timestamp < now-300 || clientHS.Timestamp > now+300 {
		// Outside 5 minute window.
		return h.writeHTTPErrorAndClose(conn, "invalid timestamp")
	}

	serverPriv, serverPub, err := generateKeyPair()
	if err != nil {
		return err
	}

	shared := deriveSharedKey(serverPriv, clientHS.PublicKey)
	sessionKey := deriveSessionKey(shared, clientHS.Nonce[:])

	user, err := h.authenticateUser(clientHS.UserID)
	if err != nil {
		// Authentication failed, behave like normal HTTP error and close.
		return h.writeHTTPErrorAndClose(conn, "forbidden")
	}

	// Build a simple JSON response; PolicyGrant is left empty for now.
	resp := ServerHandshake{
		PublicKey:   serverPub,
		PolicyGrant: nil,
	}

	respBody, err := json.Marshal(resp)
	if err != nil {
		return err
	}

	header := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
	header += strconv.Itoa(len(respBody))
	header += "\r\n\r\n"

	if _, err := conn.Write([]byte(header)); err != nil {
		return err
	}
	if _, err := conn.Write(respBody); err != nil {
		return err
	}

	// Step 3: create session and handle encrypted frames.
	session, err := reflex.NewSession(sessionKey)
	if err != nil {
		return err
	}
	return h.handleSession(ctx, reader, conn, dispatcher, session, user)
}

// handleSession reads encrypted frames and processes them by type (Data, PaddingCtrl, TimingCtrl).
func (h *Handler) handleSession(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, session *reflex.Session, user *protocol.MemoryUser) error {
	_ = user
	profile := h.defaultProfile
	for {
		frame, err := session.ReadFrame(reader)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		switch frame.Type {
		case reflex.FrameTypeData:
			if dispatcher != nil {
				dest := net.TCPDestination(net.ParseAddress("127.0.0.1"), net.Port(80))
				link, err := dispatcher.Dispatch(ctx, dest)
				if err != nil {
					continue
				}
				b := buf.New()
				b.Write(frame.Payload)
				_ = link.Writer.WriteMultiBuffer(buf.MultiBuffer{b})
				if c, ok := link.Writer.(interface{ Close() error }); ok {
					_ = c.Close()
				}
				mb, err := link.Reader.ReadMultiBuffer()
				if err == nil && !mb.IsEmpty() {
					data := make([]byte, mb.Len())
					mb.Copy(data)
					_ = reflex.WriteFrameWithMorphing(session, conn, reflex.FrameTypeData, data, profile)
					buf.ReleaseMulti(mb)
				}
			}
		case reflex.FrameTypePaddingCtrl, reflex.FrameTypeTimingCtrl:
			reflex.ApplyControlFrame(profile, frame.Type, frame.Payload)
		default:
			// Unknown frame type; ignore.
		}
	}
}

func (h *Handler) writeHTTPErrorAndClose(conn stat.Connection, reason string) error {
	body := []byte(`{"error":"` + reason + `"}`)
	resp := "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: "
	resp += strconv.Itoa(len(body))
	resp += "\r\n\r\n"
	if _, err := conn.Write([]byte(resp)); err != nil {
		_ = conn.Close()
		return err
	}
	if _, err := conn.Write(body); err != nil {
		_ = conn.Close()
		return err
	}
	return conn.Close()
}

// preloadedConn wraps a stat.Connection with a bufio.Reader so that bytes
// already peeked remain visible to the fallback target.
type preloadedConn struct {
	*bufio.Reader
	stat.Connection
}

func (pc *preloadedConn) Read(b []byte) (int, error) {
	return pc.Reader.Read(b)
}

func (pc *preloadedConn) Write(b []byte) (int, error) {
	return pc.Connection.Write(b)
}

// handleFallback forwards the connection (including already-peeked bytes)
// to a local web server defined by h.fallback.
func (h *Handler) handleFallback(ctx context.Context, reader *bufio.Reader, conn stat.Connection) error {
	if h.fallback == nil {
		_ = conn.Close()
		return errors.New("no fallback configured")
	}

	wrapped := &preloadedConn{
		Reader:     reader,
		Connection: conn,
	}

	targetAddr := fmt.Sprintf("127.0.0.1:%d", h.fallback.Dest)
	target, err := stdnet.Dial("tcp", targetAddr)
	if err != nil {
		_ = conn.Close()
		return err
	}
	defer target.Close()

	// Copy in both directions.
	errc := make(chan error, 2)

	go func() {
		_, e := io.Copy(target, wrapped)
		_ = target.(*stdnet.TCPConn).CloseWrite()
		errc <- e
	}()

	go func() {
		_, e := io.Copy(wrapped, target)
		_ = wrapped.Close()
		errc <- e
	}()

	// Wait for first copy to finish; ignore EOF-like errors.
	if e := <-errc; e != nil && !errors.Is(e, io.EOF) {
		return e
	}
	return nil
}