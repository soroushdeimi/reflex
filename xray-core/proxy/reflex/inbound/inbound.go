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
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	feature_inbound "github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/proxy/reflex/encoding"
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

	// Authenticate user
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

	var profile *encoding.TrafficProfile
	if acc, ok := user.Account.(*reflex.MemoryAccount); ok && acc.Policy != "" {
		profile = encoding.Profiles[acc.Policy]
	}
	_ = profile // Used in step 5

	// Handle the encrypted session (from step 3)
	// TODO: Step 4 - Add fallback and multiplexing
	return h.handleSession(handshakeCtx, reader, conn, dispatcher, sess, user)
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

// handleSession processes the encrypted session (from step 3)
func (h *Handler) handleSession(ctx context.Context, reader io.Reader, conn stat.Connection, dispatcher routing.Dispatcher, sess *encoding.Session, user *protocol.MemoryUser) error {
	for {
		frame, err := sess.ReadFrame(reader)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}

		switch frame.Type {
		case encoding.FrameTypeData:
			err := h.handleData(ctx, frame.Payload, conn, dispatcher, sess, user)
			if err != nil {
				return err
			}
			continue

		case encoding.FrameTypePadding:
			// ignored for now (step 5)
			continue

		case encoding.FrameTypeTiming:
			// ignored for now (step 5)
			continue

		case encoding.FrameTypeClose:
			return nil

		default:
			return errors.New("unknown frame type")
		}
	}
}

// handleData forwards data to upstream and handles responses (from step 3)
func (h *Handler) handleData(ctx context.Context, data []byte, conn stat.Connection, dispatcher routing.Dispatcher, sess *encoding.Session, user *protocol.MemoryUser) error {
	// parse destination from the data frame
	dest, remaining, err := decodeAddress(data)
	if err != nil {
		return err
	}

	// add user info to context for logging/policy
	ctx = session.ContextWithInbound(ctx, &session.Inbound{
		User: user,
	})

	// dispatch to target
	link, err := dispatcher.Dispatch(ctx, dest)
	if err != nil {
		return err
	}

	// send any remaining data that came with the first frame
	if len(remaining) > 0 {
		if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(remaining)}); err != nil {
			return err
		}
	}

	// handle responses from target: read from upstream and send back to client
	go func() {
		defer link.Writer.Close()
		for {
			mb, err := link.Reader.ReadMultiBuffer()
			if err != nil {
				return
			}
			for _, b := range mb {
				if err := sess.WriteFrame(conn, encoding.FrameTypeData, b.Bytes()); err != nil {
					return
				}
				b.Release()
			}
		}
	}()

	return nil
}

// decodeAddress parses the destination address from the first data frame (from step 3)
// format: [addrType(1)][port(2)][addr...][remaining data]
// addrType: 1=IPv4, 2=Domain, 3=IPv6
func decodeAddress(data []byte) (xnet.Destination, []byte, error) {
	if len(data) < 3 {
		return xnet.Destination{}, nil, errors.New("invalid address data: too short")
	}

	addrType := data[0]
	port := xnet.PortFromBytes(data[1:3])
	off := 3

	var addr xnet.Address

	switch addrType {
	case 1: // IPv4
		if len(data) < off+4 {
			return xnet.Destination{}, nil, errors.New("invalid IPv4 address")
		}
		addr = xnet.IPAddress(data[off : off+4])
		off += 4

	case 2: // Domain
		if len(data) < off+1 {
			return xnet.Destination{}, nil, errors.New("invalid domain address")
		}
		domainLen := int(data[off])
		off++
		if len(data) < off+domainLen {
			return xnet.Destination{}, nil, errors.New("invalid domain address")
		}
		addr = xnet.DomainAddress(string(data[off : off+domainLen]))
		off += domainLen

	case 3: // IPv6
		if len(data) < off+16 {
			return xnet.Destination{}, nil, errors.New("invalid IPv6 address")
		}
		addr = xnet.IPAddress(data[off : off+16])
		off += 16

	default:
		return xnet.Destination{}, nil, errors.New("unknown address type")
	}

	return xnet.TCPDestination(addr, port), data[off:], nil
}

// handleFallback handles non-Reflex connections (from step 2)
// TODO: Step 4 - Implement fallback to web server
func (h *Handler) handleFallback(ctx context.Context, reader *bufio.Reader, conn stat.Connection) error {
	if h.fallback == nil || h.fallback.Dest == "" {
		return errors.New("no fallback configured")
	}
	// Will be implemented in step 4
	return nil
}