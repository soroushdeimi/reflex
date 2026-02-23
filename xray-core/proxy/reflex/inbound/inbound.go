package inbound

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net/http"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport/internet/stat"
	"google.golang.org/protobuf/proto"
)

// Inbound Handler definition
type Handler struct {
	clients  []*protocol.MemoryUser
	fallback *FallbackConfig
}

type MemoryAccount struct {
	Id string
}

// Equals implements protocol.Account
func (a *MemoryAccount) Equals(account protocol.Account) bool {
	reflexAccount, ok := account.(*MemoryAccount)
	if !ok {
		return false
	}
	return a.Id == reflexAccount.Id
}

// ToProto implements protocol.Account
func (a *MemoryAccount) ToProto() proto.Message {
	return &reflex.Account{
		Id: a.Id,
	}
}

// definition of FallbackConfig struct
type FallbackConfig struct {
	Dest uint32
}

func (h *Handler) Network() []net.Network {
	return []net.Network{net.Network_TCP}
}

// Initialization
func init() {
	common.Must(common.RegisterConfig((*reflex.InboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*reflex.InboundConfig))
	}))
}

func New(ctx context.Context, config *reflex.InboundConfig) (proxy.Inbound, error) {
	handler := &Handler{
		clients: make([]*protocol.MemoryUser, 0),
	}

	// config to handler
	for _, client := range config.Clients {
		handler.clients = append(handler.clients, &protocol.MemoryUser{
			Email:   client.Id,
			Account: &MemoryAccount{Id: client.Id},
		})
	}

	// create fallback, if needed
	if config.Fallback != nil {
		handler.fallback = &FallbackConfig{
			Dest: config.Fallback.Dest,
		}
	}

	return handler, nil

}

// proccess (Second step- handshake)
func (h *Handler) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	reader := bufio.NewReader(conn)

	// Peek to check MagicNumber
	peeked, err := reader.Peek(64)
	if err != nil {
		return handleError("failed to peek")
	}

	// Check MagicNumber
	if len(peeked) >= 4 {
		magic := binary.BigEndian.Uint32(peeked[0:4])
		if magic == ReflexMagic {
			return h.handleReflexMagic(reader, conn, dispatcher, ctx)
		}
	}

	// Ckecking HTTPPostLike (The function must me implemented in step4)
	if h.isHTTPPostLike(peeked) {
		return h.handleReflexHTTP(reader, conn, dispatcher, ctx)
	}

	// Not magic, not Http-like -> send to fallback
	return h.handleFallback(ctx, reader, conn)
}

// ======== Defining handlers in proccess ========

// Before closing connection, a proper message is sent
func (h *Handler) handleFallback(ctx context.Context, reader *bufio.Reader, conn net.Conn) error {

	resp := "HTTP/1.1 403 Forbidden\r\n" +
		"Content-Length: 0\r\n" +
		"Connection: close\r\n\r\n"

	_, _ = conn.Write([]byte(resp))
	_ = conn.Close()
	return nil
}

func (h *Handler) handleReflexMagic(reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, ctx context.Context) error {
	magic := make([]byte, 4)
	io.ReadFull(reader, magic)

	var clientHS ClientHandshake

	// 32 (pubkey) + 16 (userid) + 8 (timestamp) + 16 (nonce)
	const handshakeHeaderLen = 72

	buf := make([]byte, handshakeHeaderLen)
	if _, err := io.ReadFull(reader, buf); err != nil {
		return handleError("failed to read handshake header").Base(err)
	}

	offset := 0

	// PublicKey
	copy(clientHS.PublicKey[:], buf[offset:offset+32])
	offset += 32

	// UserID
	copy(clientHS.UserID[:], buf[offset:offset+16])
	offset += 16

	// Timestamp
	clientHS.Timestamp = int64(binary.BigEndian.Uint64(buf[offset : offset+8]))
	offset += 8

	// Nonce
	copy(clientHS.Nonce[:], buf[offset:offset+16])

	return h.processHandshake(reader, conn, dispatcher, ctx, clientHS)
}

func (h *Handler) handleReflexHTTP(reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, ctx context.Context) error {

	// parse HTTP request
	req, err := http.ReadRequest(reader)
	if err != nil {
		return h.handleFallback(ctx, reader, conn)
	}

	// check if it is post request
	if req.Method != http.MethodPost {
		return h.handleFallback(ctx, reader, conn)
	}

	// reading its body
	body, err := io.ReadAll(io.LimitReader(req.Body, 8*1024))
	if err != nil {
		return h.handleFallback(ctx, reader, conn)
	}
	_ = req.Body.Close()

	if len(body) == 0 {
		return h.handleFallback(ctx, reader, conn)
	}

	// decode of base64
	rawHandshake, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(body)))
	if err != nil {
		return h.handleFallback(ctx, reader, conn)
	}

	// parse handshake using unmarshal because it is in binary form
	var clientHS ClientHandshake
	if err := clientHS.UnmarshalBinary(rawHandshake); err != nil {
		return h.handleFallback(ctx, reader, conn)
	}

	return h.processHandshake(reader, conn, dispatcher, ctx, clientHS)
}

func (h *Handler) processHandshake(reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, ctx context.Context, clientHS ClientHandshake) error {
	// generate server
	serverPrivateKey, serverPublicKey := generateKeyPair()

	// define session and shared keys
	sharedKey := deriveSharedKey(serverPrivateKey, clientHS.PublicKey)
	sessionKey := deriveSessionKey(sharedKey, []byte("reflex-session"))

	// authentication
	user, err := h.authenticateUser(clientHS.UserID)
	if err != nil {
		return h.handleFallback(ctx, reader, conn)
	}

	serverHS := ServerHandshake{
		PublicKey:   serverPublicKey,
		PolicyGrant: h.encryptPolicyGrant(user, sessionKey),
	}

	_ = serverHS

	//Send response
	response := []byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"ok\"}")
	conn.Write(response)

	// Now, handle session
	return h.handleSession(ctx, reader, conn, dispatcher, sessionKey, user)
}

func (h *Handler) handleSession(
	ctx context.Context,
	reader *bufio.Reader,
	conn stat.Connection,
	dispatcher routing.Dispatcher,
	sessionKey []byte,
	user *protocol.MemoryUser,
) error {
	//TODO
	return nil
}

// Handle Errors
func handleError(values ...interface{}) *errors.Error {
	return errors.New(values...)
}

// check if its HTTPPost-like
func (h *Handler) isHTTPPostLike(peeked []byte) bool {
	if len(peeked) < 4 {
		return false
	}
	return string(peeked[:4]) == "POST"
}
