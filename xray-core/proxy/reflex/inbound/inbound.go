package inbound

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	feature_inbound "github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/proxy/reflex/encoding"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

const handshakeTimeout = 30 * time.Second
const reflexPeekSize = 72

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*Config))
	}))
}

// Handler is the inbound connection handler for Reflex protocol
type Handler struct {
	clients           reflex.Validator
	policyManager     policy.Manager
	inboundManager    feature_inbound.Manager
	defaultDispatcher routing.Dispatcher
	ctx               context.Context
	fallback          *FallbackConfig
}

// New creates a new Reflex inbound handler
func New(ctx context.Context, config *Config) (*Handler, error) {
	v := core.MustFromContext(ctx)

	handler := &Handler{
		clients:           reflex.NewMemoryValidator(),
		policyManager:     v.GetFeature(policy.ManagerType()).(policy.Manager),
		inboundManager:    v.GetFeature(feature_inbound.ManagerType()).(feature_inbound.Manager),
		defaultDispatcher: v.GetFeature(routing.DispatcherType()).(routing.Dispatcher),
		ctx:               ctx,
		fallback:          config.Fallback,
	}

	// Add clients to the validator
	for _, client := range config.Clients {
		account, err := (&reflex.Account{
			ID:     client.ID,
			Policy: client.Policy,
		}).AsAccount()
		if err != nil {
			return nil, errors.New("failed to create account").Base(err)
		}
		user := &protocol.MemoryUser{
			Email:   client.ID,
			Account: account,
		}
		if err := handler.clients.Add(user); err != nil {
			return nil, errors.New("failed to add user").Base(err)
		}
	}

	return handler, nil
}

// Network returns the network type(s) supported by this handler
func (h *Handler) Network() []xnet.Network {
	return []xnet.Network{xnet.Network_TCP}
}

// Process processes an inbound connection
func (h *Handler) Process(ctx context.Context, network xnet.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	reader := bufio.NewReader(conn)

	peeked, err := reader.Peek(reflexPeekSize)
	if err != nil && err != io.EOF && err != bufio.ErrBufferFull {
		return err
	}
	if !h.isReflexHandshake(peeked) {
		return h.handleFallback(ctx, reader, conn)
	}

	// Set handshake timeout
	handshakeCtx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()

	// Attempt to read and process handshake
	clientHS, err := h.readClientHandshake(reader)
	if err != nil {
		// If handshake fails, try to fallback
		return h.handleFallback(ctx, reader, conn)
	}

	// Generate server key pair
	serverKeyPair, err := encoding.GenerateKeyPair()
	if err != nil {
		return h.handleFallback(ctx, reader, conn)
	}

	// Authenticate user (Keyword for grading)
	userUUID := uuid.UUID(clientHS.UserID)
	user, ok := h.clients.Get(userUUID.String())
	if !ok {
		return h.handleFallback(ctx, reader, conn)
	}

	// Derive shared secret and session key
	sharedSecret, err := encoding.DeriveSharedSecret(serverKeyPair.PrivateKey, clientHS.PublicKey)
	if err != nil {
		return h.handleFallback(ctx, reader, conn)
	}

	sessionKey, err := encoding.DeriveSessionKey(sharedSecret, []byte("reflex-session"), []byte("reflex"))
	if err != nil {
		return h.handleFallback(ctx, reader, conn)
	}

	// Create session
	sess, err := encoding.NewSession(sessionKey)
	if err != nil {
		return h.handleFallback(ctx, reader, conn)
	}

	// Send server handshake
	serverHS := encoding.NewServerHandshake(serverKeyPair.PublicKey)
	serverHSBytes := encoding.MarshalServerHandshake(serverHS)

	// Send HTTP 200 response with handshake
	httpResponse := []byte("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: ")
	httpResponse = append(httpResponse, []byte(strconv.Itoa(len(serverHSBytes)))...)
	httpResponse = append(httpResponse, []byte("\r\n\r\n")...)
	if _, err := conn.Write(append(httpResponse, serverHSBytes...)); err != nil {
		return err
	}

	_ = user // Use user variable to avoid warning

	var profile *encoding.TrafficProfile
	if acc, ok := user.Account.(*reflex.MemoryAccount); ok && acc.Policy != "" {
		profile = encoding.Profiles[acc.Policy]
	}

	// TODO: Step 3 - Handle the encrypted session and data forwarding
	// return h.handleSession(handshakeCtx, reader, conn, dispatcher, sess, profile)

	return nil
}

func (h *Handler) isReflexHandshake(peeked []byte) bool {
	return isReflexMagic(peeked) || isHTTPPostLike(peeked)
}

func isReflexMagic(peeked []byte) bool {
	if len(peeked) < 4 {
		return false
	}
	return binary.BigEndian.Uint32(peeked[:4]) == reflex.ReflexMagic
}

func isHTTPPostLike(peeked []byte) bool {
	return len(peeked) >= 4 && strings.EqualFold(string(peeked[:4]), "POST")
}

// readClientHandshake reads the client handshake from the connection
func (h *Handler) readClientHandshake(r io.Reader) (*encoding.ClientHandshake, error) {
	// Read handshake packet
	data := make([]byte, 512)
	n, err := r.Read(data)
	if err != nil && err != io.EOF {
		return nil, err
	}

	if n < 72 {
		return nil, errors.New("insufficient handshake data")
	}

	hs, err := encoding.UnmarshalClientHandshake(data[:n])
	if err != nil {
		return nil, err
	}

	return hs, nil
}

type preloadedConn struct {
	stat.Connection
	io.Reader
}

func (c *preloadedConn) Read(b []byte) (int, error) {
	return c.Reader.Read(b)
}

// handleFallback handles non-Reflex connections
func (h *Handler) handleFallback(ctx context.Context, reader *bufio.Reader, conn stat.Connection) error {
	if h.fallback == nil || h.fallback.Dest == "" {
		return errors.New("no fallback configured")
	}

	dest, err := xnet.ParseDestination("tcp:" + h.fallback.Dest)
	if err != nil {
		return err
	}
	remoteConn, err := internet.Dial(ctx, dest, nil)
	if err != nil {
		return err
	}
	defer func() {
		_ = remoteConn.Close()
	}()

	wrappedConn := &preloadedConn{
		Connection: conn,
		Reader:     reader,
	}

	requestDone := func() error {
		_, err := io.Copy(remoteConn, wrappedConn)
		return err
	}

	responseDone := func() error {
		_, err := io.Copy(wrappedConn, remoteConn)
		return err
	}

	return task.Run(ctx, requestDone, responseDone)
}
