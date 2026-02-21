<<<<<<< HEAD
package inbound

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type Handler struct {
	clients         []*protocol.MemoryUser
	fallback        *FallbackConfig
	morphingEnabled bool
}

// MemoryAccount implements protocol.Account and is used to store Reflex user information in memory.
type MemoryAccount struct {
	Id string
}

// Equals implements protocol.Account.
func (a *MemoryAccount) Equals(account protocol.Account) bool {
	other, ok := account.(*MemoryAccount)
	if !ok {
		return false
	}
	return a.Id == other.Id
}

// ToProto implements protocol.Account.
func (a *MemoryAccount) ToProto() proto.Message {
	return &reflex.Account{
		Id: a.Id,
	}
}

type FallbackConfig struct {
	Dest uint32
}

// preloadedConn wraps a bufio.Reader and the underlying connection so that Read
// uses the reader (including any peeked/buffered bytes) and Write goes to the connection.
// This ensures peeked bytes are sent to the fallback server correctly (Step 4).
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

// ReflexMinHandshakeSize is the number of bytes we try to peek for protocol
// detection. It only needs to cover the magic number, but we use a slightly
// larger value to leave room for HTTP detection in the future.
const ReflexMinHandshakeSize = 64

// Network implements proxy.Inbound.Network.
func (h *Handler) Network() []xnet.Network {
	return []xnet.Network{xnet.Network_TCP}
}

// Process implements proxy.Inbound.Process. It now performs a basic magic-number
// based Reflex handshake and authenticates the user by UUID. HTTP POST-like
// disguise and full session handling are added in later steps.
func (h *Handler) Process(ctx context.Context, network xnet.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	// Wrap connection so we can peek without consuming bytes irreversibly.
	reader := bufio.NewReader(conn)

	// Peek a small prefix for magic / HTTP detection.
	peeked, err := reader.Peek(ReflexMinHandshakeSize)
	if err != nil {
		return err
	}

	// Decide whether this looks like Reflex traffic.
	if h.isReflexHandshake(peeked) {
		// Prefer fast magic-number path.
		if h.isReflexMagic(peeked) {
			return h.handleReflexMagic(ctx, reader, conn, dispatcher)
		}
		// HTTP POST-like path can be implemented later; fall back for now.
		return h.handleFallback(ctx, reader, conn)
	}

	// Not Reflex: forward to fallback web server (if configured).
	return h.handleFallback(ctx, reader, conn)
}

func init() {
	common.Must(common.RegisterConfig((*reflex.InboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*reflex.InboundConfig))
	}))
}

<<<<<<< HEAD
// New creates a new Reflex inbound handler from the generated InboundConfig.
func New(ctx context.Context, config *reflex.InboundConfig) (*Handler, error) {
	_ = ctx
	handler := &Handler{
		clients:         make([]*protocol.MemoryUser, 0, len(config.Clients)),
		morphingEnabled: config.GetMorphingEnabled(),
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

	return handler, nil
}

// handleReflexMagic parses the magic-number based ClientHandshakePacket,
// derives a session key and authenticates the user. The established session
// handling is deferred to later steps.
func (h *Handler) handleReflexMagic(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher) error {
	// Read and discard the 4-byte magic (we already checked it via Peek).
	magic := make([]byte, 4)
	if _, err := io.ReadFull(reader, magic); err != nil {
		return err
	}

	// Read the fixed-size part of the handshake packet (everything except PolicyReq).
	const fixedSize = 32 + 16 + 8 + 16 + 4 // fields after magic
	fixed := make([]byte, fixedSize)
	if _, err := io.ReadFull(reader, fixed); err != nil {
		return h.handleFallback(ctx, reader, conn)
	}

	// Extract PolicyReq length from the last 4 bytes.
	policyLen := int(binary.BigEndian.Uint32(fixed[fixedSize-4:]))
	if policyLen < 0 || policyLen > 1024 {
		return h.handleFallback(ctx, reader, conn)
	}

	policy := make([]byte, policyLen)
	if policyLen > 0 {
		if _, err := io.ReadFull(reader, policy); err != nil {
			return h.handleFallback(ctx, reader, conn)
		}
	}

	data := make([]byte, 0, 4+len(fixed)+len(policy))
	data = append(data, magic...)
	data = append(data, fixed...)
	data = append(data, policy...)

	packet, err := reflex.DecodeClientHandshakePacket(data)
	if err != nil {
		return h.handleFallback(ctx, reader, conn)
	}

	// Generate server key pair and derive session key.
	serverPriv, serverPub, err := reflex.GenerateKeyPair()
	if err != nil {
		return h.handleFallback(ctx, reader, conn)
	}
	shared := reflex.DeriveSharedKey(serverPriv, packet.Handshake.PublicKey)
	sessionKey := reflex.DeriveSessionKey(shared, []byte("reflex-session"))
	if sessionKey == nil {
		return h.handleFallback(ctx, reader, conn)
	}

	// Authenticate user by UUID. On failure send HTTP 403 then close (per Step 2).
	user, err := h.authenticateUser(packet.Handshake.UserID)
	if err != nil {
		_, _ = conn.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"))
		return nil
	}

	// Send HTTP-like 200 OK with ServerHandshake: server public key (and optional policy grant).
	body := fmt.Sprintf(`{"status":"ok","publicKey":"%s"}`, base64.StdEncoding.EncodeToString(serverPub[:]))
	resp := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
	if _, err := conn.Write([]byte(resp)); err != nil {
		return err
	}

	// Start encrypted session processing (Step 3: dispatch DATA to upstream).
	return h.handleSession(ctx, reader, conn, dispatcher, sessionKey, user)
}

// authenticateUser searches for a MemoryUser whose account UUID matches the raw UUID bytes.
func (h *Handler) authenticateUser(userID [16]byte) (*protocol.MemoryUser, error) {
	id := uuid.UUID(userID).String()
	for _, u := range h.clients {
		accountID := u.Account.(*MemoryAccount).Id
		if accountID == id {
			return u, nil
		}
	}
	return nil, errors.New("user not found")
}

// handleFallback forwards traffic to the configured fallback web server (Step 4).
// Uses preloadedConn so peeked bytes are read from the reader and sent to fallback.
func (h *Handler) handleFallback(ctx context.Context, reader *bufio.Reader, conn stat.Connection) error {
	_ = ctx
	if h.fallback == nil || h.fallback.Dest == 0 {
		return errors.New("no fallback configured")
	}

	wrappedConn := &preloadedConn{
		Reader:     reader,
		Connection: conn,
	}

	target := net.JoinHostPort("127.0.0.1", strconv.FormatUint(uint64(h.fallback.Dest), 10))
	fbConn, err := net.Dial("tcp", target)
	if err != nil {
		return err
	}
	defer fbConn.Close()

	// Bidirectional copy: client (wrappedConn, including peeked bytes) <-> fallback server.
	go io.Copy(fbConn, wrappedConn)
	_, _ = io.Copy(wrappedConn, fbConn)
	return nil
}

// isReflexMagic checks for the Reflex magic number at the start of the buffer.
func (h *Handler) isReflexMagic(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	magic := binary.BigEndian.Uint32(data[0:4])
	return magic == reflex.ReflexMagic
}

// isHTTPPostLike performs a shallow check whether the buffer looks like an
// HTTP POST request. This is a placeholder for a future HTTP-based handshake.
func (h *Handler) isHTTPPostLike(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	if string(data[0:4]) != "POST" {
		return false
	}
	return true
}

// isReflexHandshake combines both magic-number and HTTP POST-like detection.
func (h *Handler) isReflexHandshake(data []byte) bool {
	if h.isReflexMagic(data) {
		return true
	}
	if h.isHTTPPostLike(data) {
		return true
	}
	return false
}

// parseReflexDestination parses a destination from the start of a DATA payload.
// Format: [1 byte addrType][addrType 0: 1 byte len + domain][1: 4 bytes IPv4][2: 16 bytes IPv6][2 bytes port BE][rest = data]
// Returns (dest, rest, nil) or (zero, nil, err).
func parseReflexDestination(data []byte) (xnet.Destination, []byte, error) {
	if len(data) < 1 {
		return xnet.Destination{}, nil, errors.New("reflex: payload too short for destination")
	}
	atype := data[0]
	offset := 1
	var addr xnet.Address
	switch atype {
	case 0: // domain
		if len(data) < 2 {
			return xnet.Destination{}, nil, errors.New("reflex: domain length missing")
		}
		domainLen := int(data[1])
		offset = 2 + domainLen
		if len(data) < offset {
			return xnet.Destination{}, nil, errors.New("reflex: domain truncated")
		}
		addr = xnet.DomainAddress(string(data[2 : 2+domainLen]))
	case 1: // IPv4
		if len(data) < 1+4+2 {
			return xnet.Destination{}, nil, errors.New("reflex: IPv4 address truncated")
		}
		addr = xnet.IPAddress(append([]byte(nil), data[1:5]...))
		offset = 5
	case 2: // IPv6
		if len(data) < 1+16+2 {
			return xnet.Destination{}, nil, errors.New("reflex: IPv6 address truncated")
		}
		addr = xnet.IPAddress(append([]byte(nil), data[1:17]...))
		offset = 17
	default:
		return xnet.Destination{}, nil, errors.New("reflex: unknown address type")
	}
	if len(data) < offset+2 {
		return xnet.Destination{}, nil, errors.New("reflex: port missing")
	}
	port := xnet.PortFromBytes(data[offset : offset+2])
	offset += 2
	dest := xnet.TCPDestination(addr, port)
	rest := data[offset:]
	return dest, rest, nil
}

// handleData establishes an upstream link from the first DATA payload (destination + data),
// writes the initial data to upstream, and starts a goroutine to copy upstream -> client as encrypted frames.
// If profile is non-nil, responses are sent with WriteFrameWithMorphing (Step 5 traffic morphing).
// Returns the link for subsequent DATA frames, or (nil, err).
func (h *Handler) handleData(ctx context.Context, data []byte, conn stat.Connection, dispatcher routing.Dispatcher, sess *reflex.Session, user *protocol.MemoryUser, profile *reflex.TrafficProfile) (*transport.Link, error) {
	_ = user
	dest, rest, err := parseReflexDestination(data)
	if err != nil {
		return nil, err
	}

	link, err := dispatcher.Dispatch(ctx, dest)
	if err != nil {
		return nil, err
	}

	// Write initial payload to upstream.
	if len(rest) > 0 {
		b := buf.New()
		if _, err := b.Write(rest); err != nil {
			_ = common.Close(link.Writer)
			return nil, err
		}
		if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
			return nil, err
		}
	}

	// Goroutine: read from upstream, encrypt and write to client (with morphing if enabled).
	go func() {
		defer common.Close(link.Writer)
		for {
			mb, err := link.Reader.ReadMultiBuffer()
			if err != nil {
				return
			}
			for _, b := range mb {
				payload := b.Bytes()
				b.Release()
				if profile != nil {
					if err := sess.WriteFrameWithMorphing(conn, reflex.FrameTypeData, payload, profile); err != nil {
						return
					}
				} else {
					if err := sess.WriteFrame(conn, reflex.FrameTypeData, payload); err != nil {
						return
					}
				}
			}
		}
	}()

	return link, nil
}

// handleSession reads encrypted frames from the client, dispatches DATA to upstream, and bridges responses back.
// Uses traffic morphing if enabled in config.
func (h *Handler) handleSession(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, sessionKey []byte, user *protocol.MemoryUser) error {
	sess, err := reflex.NewSession(sessionKey)
	if err != nil {
		return err
	}

	// Per-connection profile for traffic morphing (only if enabled).
	var profile *reflex.TrafficProfile
	if h.morphingEnabled {
		profile = &reflex.TrafficProfile{
			Name:        reflex.HTTP2APIProfile.Name,
			PacketSizes: reflex.HTTP2APIProfile.PacketSizes,
			Delays:      reflex.HTTP2APIProfile.Delays,
		}
	}

	var link *transport.Link

	for {
		frame, err := sess.ReadFrame(reader)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}

		switch frame.Type {
		case reflex.FrameTypeData:
			// Strip traffic morphing prefix if morphing is enabled.
			payload := frame.Payload
			if h.morphingEnabled {
				if stripped, ok := reflex.StripMorphingPrefix(payload); ok {
					payload = stripped
				}
			}
			if link == nil {
				link, err = h.handleData(ctx, payload, conn, dispatcher, sess, user, profile)
				if err != nil {
					return err
				}
			} else {
				if len(payload) > 0 {
					b := buf.New()
					if _, err := b.Write(payload); err != nil {
						return err
					}
					if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
						return err
					}
				}
			}
		case reflex.FrameTypePadding, reflex.FrameTypeTiming:
			if profile != nil {
				sess.HandleControlFrame(frame, profile)
			}
		case reflex.FrameTypeClose:
			if link != nil {
				_ = common.Close(link.Writer)
			}
			return nil
		default:
			return errors.New("unknown frame type")
		}
	}
}
