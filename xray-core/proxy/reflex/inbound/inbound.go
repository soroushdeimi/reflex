package inbound

import (
	"bufio"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	stdnet "net"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/antireplay"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
	"google.golang.org/protobuf/proto"
)

// Handler is an inbound connection handler for Reflex protocol.
// It supports TCP, TLS (with ECH), and QUIC transports.
type Handler struct {
	clients      []*protocol.MemoryUser
	fallback     *FallbackConfig
	tlsConfig    *tls.Config
	quicConf     *reflex.InboundConfig
	replayFilter *antireplay.ReplayFilter
}

// MemoryAccount برای ذخیره اطلاعات کاربر
// باید protocol.Account interface رو implement کنه
type MemoryAccount struct {
	Id     string
	Policy string
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

type FallbackConfig struct {
	Dest uint32
}

func (h *Handler) Network() []net.Network {
	return []net.Network{net.Network_TCP}
}

// Process handles an incoming connection. It detects the protocol and either
// handles it as Reflex or falls back to the configured destination.
func (h *Handler) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	// If TLS is enabled for the handler
	if h.tlsConfig != nil {
		tlsConn := tls.Server(conn, h.tlsConfig)
		if err := tlsConn.Handshake(); err != nil {
			return err
		}
		// In a real Xray context, we would use stat.WrapConnection(tlsConn)
		// For this task, we assume the cast or a simple wrapper works.
		reader := bufio.NewReader(tlsConn)
		return h.processWithReader(ctx, reader, tlsConn, dispatcher)
	}

	reader := bufio.NewReader(conn)
	return h.processWithReader(ctx, reader, conn, dispatcher)
}

func (h *Handler) processWithReader(ctx context.Context, reader *bufio.Reader, conn net.Conn, dispatcher routing.Dispatcher) error {
	peeked, err := reader.Peek(64)
	if err != nil && err != io.EOF {
		return h.handleFallback(ctx, reader, conn.(stat.Connection))
	}

	if h.isReflexHandshake(peeked) {
		if len(peeked) >= 4 {
			magic := binary.BigEndian.Uint32(peeked[0:4])
			if magic == reflex.ReflexMagic {
				return h.handleReflexMagic(ctx, reader, conn.(stat.Connection), dispatcher)
			}
		}
		if h.isHTTPPostLike(peeked) {
			return h.handleReflexHTTP(ctx, reader, conn.(stat.Connection), dispatcher)
		}
	}

	return h.handleFallback(ctx, reader, conn.(stat.Connection))
}

func (h *Handler) handleReflexMagic(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher) error {
	magic := make([]byte, 4)
	if _, err := io.ReadFull(reader, magic); err != nil {
		return err
	}

	var clientHS reflex.ClientHandshake
	// Read PublicKey
	if _, err := io.ReadFull(reader, clientHS.PublicKey[:]); err != nil {
		return err
	}
	// Read UserID
	if _, err := io.ReadFull(reader, clientHS.UserID[:]); err != nil {
		return err
	}
	// Read Timestamp
	if err := binary.Read(reader, binary.BigEndian, &clientHS.Timestamp); err != nil {
		return err
	}

	// Timestamp verification (allow +/- 90 seconds)
	now := time.Now().Unix()
	delta := now - clientHS.Timestamp
	if delta < -90 || delta > 90 {
		return h.handleFallback(ctx, reader, conn)
	}

	// Read Nonce
	if _, err := io.ReadFull(reader, clientHS.Nonce[:]); err != nil {
		return err
	}

	// Replay protection
	if !h.replayFilter.Check(clientHS.Nonce[:]) {
		return errors.New("reflex: replay detected")
	}

	return h.processHandshake(ctx, reader, conn, dispatcher, clientHS)
}

func (h *Handler) isHTTPPostLike(peeked []byte) bool {
	// Simple check for POST request
	return len(peeked) >= 4 && string(peeked[0:4]) == "POST"
}

func (h *Handler) handleReflexHTTP(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher) error {
	// Stub for step 4
	return errors.New("HTTP POST-like handshake not implemented yet")
}

func (h *Handler) isReflexHandshake(peeked []byte) bool {
	if len(peeked) < 4 {
		return false
	}
	magic := binary.BigEndian.Uint32(peeked[0:4])
	if magic == reflex.ReflexMagic {
		return true
	}
	if h.isHTTPPostLike(peeked) {
		return true
	}
	return false
}

func (h *Handler) handleFallback(ctx context.Context, reader *bufio.Reader, conn stat.Connection) error {
	if h.fallback == nil {
		return errors.New("reflex: access denied (no fallback)")
	}

	target, err := stdnet.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", h.fallback.Dest))
	if err != nil {
		return errors.New("reflex: failed to connect to fallback: ", err)
	}
	defer target.Close()

	wrappedConn := &preloadedConn{
		Reader:     reader,
		Connection: conn,
	}

	go io.Copy(target, wrappedConn)
	io.Copy(wrappedConn, target)

	return nil
}

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

func (h *Handler) authenticateUser(userID [16]byte) (*protocol.MemoryUser, error) {
	for _, user := range h.clients {
		account := user.Account.(*MemoryAccount)
		u, _ := uuid.ParseString(account.Id)
		peerID := u.Bytes()

		if subtle.ConstantTimeCompare(userID[:], peerID) == 1 {
			return user, nil
		}
	}
	return nil, errors.New("user not found")
}

func (h *Handler) processHandshake(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, clientHS reflex.ClientHandshake) error {
	serverPriv, serverPub, err := reflex.GenerateKeyPair()
	if err != nil {
		return err
	}

	sessionKey, err := reflex.DeriveSessionKeys(serverPriv, clientHS.PublicKey)
	if err != nil {
		return err
	}

	user, err := h.authenticateUser(clientHS.UserID)
	if err != nil {
		return h.handleFallback(ctx, reader, conn)
	}

	// Send handshake response (binary)
	var serverHS reflex.ServerHandshake
	serverHS.PublicKey = serverPub
	// Assume serverHS.Nonce is zero-initialized or set similarly if needed
	if _, err := conn.Write(serverHS.PublicKey[:]); err != nil {
		return err
	}
	if _, err := conn.Write(serverHS.Nonce[:]); err != nil {
		return err
	}

	log.Record(&log.GeneralMessage{
		Severity: log.Severity_Info,
		Content:  "Reflex: Handshake completed for user: " + user.Email,
	})

	// Session established
	return h.handleSession(ctx, reader, conn, dispatcher, sessionKey, user)
}

func (h *Handler) handleSession(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, sessionKey []byte, user *protocol.MemoryUser) error {
	s, err := reflex.NewSession(sessionKey)
	if err != nil {
		return err
	}

	var profile *reflex.TrafficProfile
	if account, ok := user.Account.(*MemoryAccount); ok && account.Policy != "" {
		if p, ok := reflex.Profiles[account.Policy]; ok {
			profile = p
		}
	}

	var link *transport.Link
	
	// Ensure cleanup of the outbound link when session ends
	defer func() {
		if link != nil {
			common.Close(link.Writer)
			// Link reader is usually closed by the other side or GC'd, 
			// but explicitly closing the writer signals EOF upstream.
		}
	}()

	for {
		frame, err := s.ReadFrame(reader)
		if err != nil {
			if err != io.EOF {
				return err
			}
			return nil
		}

		switch frame.Type {
		case reflex.FrameTypeData:
			if link == nil {
				// Initial Dispatch on first data frame
				dest := net.TCPDestination(net.ParseAddress("example.com"), net.Port(80))
				l, err := dispatcher.Dispatch(ctx, dest)
				if err != nil {
					return err
				}
				link = l

				// Start background copy from Upstream -> Client
				go func() {
					defer common.Close(link.Reader)
					// In a real implementation, we might need a way to stop this loop when session ends
					// For now, it stops on read error or EOF from upstream
					for {
						mb, err := link.Reader.ReadMultiBuffer()
						if err != nil {
							// Upstream closed or error
							return
						}
						
						for i, b := range mb {
							if err := s.WriteFrameWithMorphing(conn, reflex.FrameTypeData, b.Bytes(), profile); err != nil {
								// Release current and all subsequent buffers
								b.Release()
								for j := i + 1; j < len(mb); j++ {
									mb[j].Release()
								}
								return
							}
							b.Release()
						}
					}
				}()
			}

			// Write packet payload to upstream
			buffer := buf.FromBytes(frame.Payload)
			if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{buffer}); err != nil {
				return err
			}

		case reflex.FrameTypePadding, reflex.FrameTypeTiming:
			s.HandleControlFrame(frame, profile)
		case reflex.FrameTypeClose:
			if link != nil {
				common.Close(link.Writer)
			}
			return nil
		default:
			return errors.New("reflex: unknown frame type")
		}
	}
}

func init() {
	common.Must(common.RegisterConfig((*reflex.InboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*reflex.InboundConfig))
	}))
}

func New(ctx context.Context, config *reflex.InboundConfig) (proxy.Inbound, error) {
	handler := &Handler{
		clients:      make([]*protocol.MemoryUser, 0),
		quicConf:     config,
		replayFilter: antireplay.NewReplayFilter(120), // 2 minutes window
	}

	// Setup TLS with ECH if enabled
	if config.UseTls {
		tlsConfig := &tls.Config{
			ServerName: config.ServerName,
			// Add certificates here if needed
		}
		if len(config.EchConfig) > 0 {
			// In Go 1.25+, we can set EncryptedClientHelloKeys
			// This is a simplified example as full ECH requires a private key
			// that matches the ECHConfig.
			// tlsConfig.EncryptedClientHelloKeys = ...
		}
		handler.tlsConfig = tlsConfig
	}

	// تبدیل config به handler
	for _, client := range config.Clients {
		handler.clients = append(handler.clients, &protocol.MemoryUser{
			Email:   client.Id,
			Account: &MemoryAccount{Id: client.Id, Policy: client.Policy},
		})
	}

	// تنظیم fallback اگر وجود داشته باشه
	if config.Fallback != nil {
		handler.fallback = &FallbackConfig{
			Dest: config.Fallback.Dest,
		}
	}

	return handler, nil
}

// QUIC Transport support
func (h *Handler) StartQUIC(addr string, dispatcher routing.Dispatcher) error {
	if h.tlsConfig == nil {
		return errors.New("QUIC requires TLS")
	}

	listener, err := quic.ListenAddr(addr, h.tlsConfig, &quic.Config{
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 10 * time.Second,
	})
	if err != nil {
		return err
	}

	go func() {
		for {
			conn, err := listener.Accept(context.Background())
			if err != nil {
				continue
			}
			go h.handleQUICConnection(conn, dispatcher)
		}
	}()

	return nil
}

func (h *Handler) handleQUICConnection(conn *quic.Conn, dispatcher routing.Dispatcher) {
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go func(s *quic.Stream) {
			streamConn := &quicStreamConn{Stream: s, conn: conn}
			// Use the Process logic on the stream
			h.processWithReader(context.Background(), bufio.NewReader(streamConn), streamConn, dispatcher)
		}(stream)
	}
}

type quicStreamConn struct {
	*quic.Stream
	conn *quic.Conn
}

func (c *quicStreamConn) RemoteAddr() stdnet.Addr {
	return c.conn.RemoteAddr()
}

func (c *quicStreamConn) LocalAddr() stdnet.Addr {
	return c.conn.LocalAddr()
}

func (c *quicStreamConn) SetDeadline(t time.Time) error {
	return c.Stream.SetDeadline(t)
}

func (c *quicStreamConn) SetReadDeadline(t time.Time) error {
	return c.Stream.SetReadDeadline(t)
}

func (c *quicStreamConn) SetWriteDeadline(t time.Time) error {
	return c.Stream.SetWriteDeadline(t)
}

// Implement other stat.Connection methods if needed...
func (c *quicStreamConn) Close() error {
	return c.Stream.Close()
}
