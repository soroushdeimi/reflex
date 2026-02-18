package inbound

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"io"
	stdnet "net"
	"strconv"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// Handler is the Reflex inbound connection handler.
type Handler struct {
	clients  []*protocol.MemoryUser
	fallback *FallbackConfig
}

// MemoryAccount implements protocol.Account for Reflex.
type MemoryAccount struct {
	Id     string
	Policy string
}

// Equals implements protocol.Account.
func (a *MemoryAccount) Equals(account protocol.Account) bool {
	reflexAccount, ok := account.(*MemoryAccount)
	if !ok {
		return false
	}
	return a.Id == reflexAccount.Id
}

// ToProto implements protocol.Account.
func (a *MemoryAccount) ToProto() proto.Message {
	return &reflex.Account{
		Id: a.Id,
	}
}

// FallbackConfig holds fallback destination (e.g. port for web server).
type FallbackConfig struct {
	Dest uint32
}

// Network implements proxy.Inbound.
func (h *Handler) Network() []net.Network {
	return []net.Network{net.Network_TCP}
}

// Process implements proxy.Inbound.
func (h *Handler) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	reader := bufio.NewReader(conn)
	// Peek only 4 bytes for protocol detection so we don't block when client sends wrong magic only.
	peeked, err := reader.Peek(4)
	if err != nil && err != io.EOF {
		return err
	}
	if len(peeked) < 4 {
		return h.handleFallbackOrReject(ctx, reader, conn)
	}
	magic := binary.BigEndian.Uint32(peeked[0:4])
	if magic == ReflexMagic {
		// Need full handshake size before reading handshake.
		peeked, err = reader.Peek(MinHandshakeSize)
		if err != nil && err != io.EOF {
			return err
		}
		if len(peeked) < MinHandshakeSize {
			return h.handleFallbackOrReject(ctx, reader, conn)
		}
		return h.handleReflexMagic(ctx, reader, conn, dispatcher)
	}
	if h.isHTTPPostLike(peeked) {
		return h.handleReflexHTTP(ctx, reader, conn, dispatcher)
	}
	return h.handleFallbackOrReject(ctx, reader, conn)
}

func (h *Handler) isHTTPPostLike(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	return string(data[0:4]) == "POST"
}

func (h *Handler) handleReflexMagic(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher) error {
	clientHS, err := readClientHandshakeMagic(reader)
	if err != nil {
		return h.handleFallbackOrReject(ctx, reader, conn)
	}
	return h.processHandshake(ctx, reader, conn, dispatcher, clientHS)
}

func (h *Handler) handleReflexHTTP(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher) error {
	// Parse HTTP POST request to extract base64-encoded handshake
	// Expected format: POST /path with body containing base64 handshake data
	
	// Read HTTP request line
	line, err := reader.ReadString('\n')
	if err != nil {
		return h.handleFallbackOrReject(ctx, reader, conn)
	}
	
	// Verify it's POST
	if len(line) < 4 || line[0:4] != "POST" {
		return h.handleFallbackOrReject(ctx, reader, conn)
	}
	
	// Read headers to find Content-Length
	var contentLength int64
	for {
		line, err := reader.ReadString('\n')
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}
		// Simple Content-Length parsing
		if len(line) > 16 && (line[0:14] == "Content-Length" || line[0:14] == "content-length") {
			// Parse: "Content-Length: 123\r\n"
			parts := bytes.Split([]byte(line), []byte(":"))
			if len(parts) >= 2 {
				val := bytes.TrimSpace(parts[1])
				contentLength, _ = strconv.ParseInt(string(val), 10, 64)
			}
		}
	}
	
	// If no body or too short, fall back
	if contentLength == 0 || contentLength > 65536 {
		return h.handleFallbackOrReject(ctx, reader, conn)
	}
	
	// Read body (base64 encoded handshake)
	body := make([]byte, contentLength)
	if _, err := io.ReadFull(reader, body); err != nil {
		return h.handleFallbackOrReject(ctx, reader, conn)
	}
	
	// Decode base64
	decoded, err := base64.StdEncoding.DecodeString(string(body))
	if err != nil {
		return h.handleFallbackOrReject(ctx, reader, conn)
	}
	
	// Parse as Reflex handshake: magic(4) + pubkey(32) + userid(16) + timestamp(8) + nonce(16) = 76 bytes
	if len(decoded) < MinHandshakeSize {
		return h.handleFallbackOrReject(ctx, reader, conn)
	}
	
	// Create buffer with decoded data for reading
	decodedReader := bufio.NewReader(bytes.NewReader(decoded))
	
	// Read and verify magic
	var magic [4]byte
	if _, err := io.ReadFull(decodedReader, magic[:]); err != nil {
		return h.handleFallbackOrReject(ctx, reader, conn)
	}
	if binary.BigEndian.Uint32(magic[:]) != ReflexMagic {
		return h.handleFallbackOrReject(ctx, reader, conn)
	}
	
	// Parse handshake
	hs := &ClientHandshake{}
	if _, err := io.ReadFull(decodedReader, hs.PublicKey[:]); err != nil {
		return h.handleFallbackOrReject(ctx, reader, conn)
	}
	if _, err := io.ReadFull(decodedReader, hs.UserID[:]); err != nil {
		return h.handleFallbackOrReject(ctx, reader, conn)
	}
	if err := binary.Read(decodedReader, binary.BigEndian, &hs.Timestamp); err != nil {
		return h.handleFallbackOrReject(ctx, reader, conn)
	}
	if _, err := io.ReadFull(decodedReader, hs.Nonce[:]); err != nil {
		return h.handleFallbackOrReject(ctx, reader, conn)
	}
	
	// Process handshake normally
	return h.processHandshake(ctx, reader, conn, dispatcher, hs)
}

func (h *Handler) processHandshake(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, clientHS *ClientHandshake) error {
	serverPriv, serverPub, err := generateKeyPair()
	if err != nil {
		return err
	}
	shared := deriveSharedKey(serverPriv, clientHS.PublicKey)
	sessionKey := deriveSessionKey(shared, []byte("reflex-session"))

	user := h.authenticateUser(clientHS.UserID)
	if user == nil {
		return h.handleFallbackOrReject(ctx, reader, conn)
	}

	serverHS := &ServerHandshake{
		PublicKey:   serverPub,
		PolicyGrant: []byte{},
	}
	if err := writeServerHandshakeMagic(conn, serverHS); err != nil {
		return err
	}

	return h.handleSession(ctx, reader, conn, dispatcher, sessionKey, user)
}

// handleSession runs after handshake: first DATA frame has target; then frame loop forwards to same link.
func (h *Handler) handleSession(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, sessionKey []byte, user *protocol.MemoryUser) error {
	session, err := NewSession(sessionKey)
	if err != nil {
		return err
	}
	profile := h.getProfile(user.Account.(*MemoryAccount).Policy)
	// First frame must be DATA with destination
	frame, err := session.ReadFrame(reader)
	if err != nil {
		return err
	}
	if frame.Type != FrameTypeData {
		return errors.New("reflex: first frame must be DATA")
	}
	return h.handleDataFrame(ctx, frame.Payload, reader, conn, dispatcher, session, user, profile)
}

// handleDataFrame parses destination from first payload, dispatches, forwards first chunk and then loops on more frames.
func (h *Handler) handleDataFrame(ctx context.Context, firstPayload []byte, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, session *Session, user *protocol.MemoryUser, profile *TrafficProfile) error {
	if len(firstPayload) < 4 {
		return nil
	}
	addrType := firstPayload[0]
	var dest net.Destination
	var dataStart int
	switch addrType {
	case 1: // IPv4
		if len(firstPayload) < 7 {
			return nil
		}
		dest = net.TCPDestination(net.IPAddress(firstPayload[1:5]), net.Port(binary.BigEndian.Uint16(firstPayload[5:7])))
		dataStart = 7
	case 2: // domain
		domainLen := int(firstPayload[1])
		if len(firstPayload) < 2+domainLen+2 {
			return nil
		}
		dest = net.TCPDestination(net.DomainAddress(string(firstPayload[2:2+domainLen])), net.Port(binary.BigEndian.Uint16(firstPayload[2+domainLen:4+domainLen])))
		dataStart = 4 + domainLen
	case 3: // IPv6
		if len(firstPayload) < 19 {
			return nil
		}
		dest = net.TCPDestination(net.IPAddress(firstPayload[1:17]), net.Port(binary.BigEndian.Uint16(firstPayload[17:19])))
		dataStart = 19
	default:
		return nil
	}
	link, err := dispatcher.Dispatch(ctx, dest)
	if err != nil {
		return err
	}

	if dataStart < len(firstPayload) {
		b := buf.FromBytes(firstPayload[dataStart:])
		if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
			return err
		}
	}

	// Downlink: upstream -> client (encrypted frames, with optional morphing)
	go func() {
		for {
			mb, err := link.Reader.ReadMultiBuffer()
			if err != nil || mb.IsEmpty() {
				return
			}
			for _, b := range mb {
				if b.Len() > 0 {
					data, delay := profile.ApplyMorphing(b.Bytes())
					_ = session.WriteFrame(conn, FrameTypeData, data)
					if delay > 0 {
						time.Sleep(delay)
					}
				}
				b.Release()
			}
		}
	}()

	// Uplink: more frames from client -> link.Writer or control
	for {
		frame, err := session.ReadFrame(reader)
		if err != nil {
			return err
		}
		switch frame.Type {
		case FrameTypeData:
			if len(frame.Payload) > 0 {
				b := buf.FromBytes(frame.Payload)
				if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
					return err
				}
			}
		case FrameTypePadding, FrameTypeTiming:
			h.handleControlFrame(frame, profile)
			continue
		case FrameTypeClose:
			return nil
		default:
			return errors.New("reflex: unknown frame type").AtWarning()
		}
	}
}

// handleFallbackOrReject sends to fallback if configured, otherwise rejects.
func (h *Handler) handleFallbackOrReject(ctx context.Context, reader *bufio.Reader, conn stat.Connection) error {
	if h.fallback != nil {
		return h.handleFallback(ctx, reader, conn)
	}
	return errNotReflex
}

// handleFallback forwards the connection to the fallback destination (e.g. web server).
func (h *Handler) handleFallback(ctx context.Context, reader *bufio.Reader, conn stat.Connection) error {
	target, err := stdnet.Dial("tcp", stdnet.JoinHostPort("127.0.0.1", strconv.Itoa(int(h.fallback.Dest))))
	if err != nil {
		return err
	}
	defer target.Close()

	wrapped := &preloadedConn{Reader: reader, Connection: conn}
	go io.Copy(target, wrapped)
	_, _ = io.Copy(wrapped, target)
	return nil
}

// preloadedConn exposes Read from the bufio.Reader (so peeked bytes are replayed) and Write from the connection.
type preloadedConn struct {
	*bufio.Reader
	stat.Connection
}

func (c *preloadedConn) Read(p []byte) (int, error) {
	return c.Reader.Read(p)
}

func (c *preloadedConn) Write(p []byte) (int, error) {
	return c.Connection.Write(p)
}

func init() {
	common.Must(common.RegisterConfig((*reflex.InboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*reflex.InboundConfig))
	}))
}

// New creates a new Reflex inbound handler from the given config.
func New(ctx context.Context, config *reflex.InboundConfig) (proxy.Inbound, error) {
	handler := &Handler{
		clients: make([]*protocol.MemoryUser, 0, len(config.GetClients())),
	}

	for _, client := range config.GetClients() {
		if client == nil {
			continue
		}
		handler.clients = append(handler.clients, &protocol.MemoryUser{
			Email:   client.GetId(),
			Account: &MemoryAccount{Id: client.GetId(), Policy: client.GetPolicy()},
		})
	}

	if config.GetFallback() != nil {
		handler.fallback = &FallbackConfig{
			Dest: config.GetFallback().GetDest(),
		}
	}

	return handler, nil
}
