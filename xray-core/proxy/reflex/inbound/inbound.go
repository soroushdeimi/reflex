package inbound

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport/internet/stat"
	"google.golang.org/protobuf/proto"
)

// Handler implements the Reflex inbound handler.
type Handler struct {
	clientsByID map[[16]byte]clientEntry
	fallback    *FallbackConfig
	nonceCache  *NonceCache
}

type clientEntry struct {
	user   *protocol.MemoryUser
	policy string
}

// MemoryAccount stores user UUID.
// It implements protocol.Account.
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
	return &reflex.Account{Id: a.Id}
}

// FallbackConfig configures fallback.
type FallbackConfig struct {
	Dest uint32
}

func (h *Handler) Network() []xnet.Network { return []xnet.Network{xnet.Network_TCP} }

// Process handles an incoming TCP connection.
func (h *Handler) Process(ctx context.Context, network xnet.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	_ = network

	reader := bufio.NewReader(conn)
	peeked, err := reader.Peek(reflex.MinHandshakePeek)
	if err != nil {
		// If the client disconnects early, just return.
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}

	// Fast path: magic number.
	if len(peeked) >= 4 {
		magic := binary.BigEndian.Uint32(peeked[0:4])
		if magic == reflex.ReflexMagic {
			return h.handleReflexMagic(ctx, reader, conn, dispatcher)
		}
	}

	// Stealth path: HTTP POST-like.
	if h.isHTTPPostLike(peeked) {
		return h.handleReflexHTTP(ctx, reader, conn, dispatcher)
	}

	// Not Reflex.
	return h.handleFallback(ctx, reader, conn)
}

func (h *Handler) isHTTPPostLike(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	return string(data[:4]) == "POST"
}

func (h *Handler) handleReflexMagic(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher) error {
	clientHS, err := reflex.ReadClientHandshakeMagic(reader)
	if err != nil {
		// If parsing fails, fallback for stealth.
		return h.handleFallback(ctx, reader, conn)
	}
	return h.processHandshake(ctx, reader, conn, dispatcher, clientHS)
}

func (h *Handler) handleReflexHTTP(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher) error {
	// IMPORTANT:
	// This function must preserve consumed bytes for robust fallback.
	// If this is a real HTTP POST (not Reflex), parsing will fail after consuming bytes from reader.
	// We must forward those raw bytes to fallback server, otherwise the request gets truncated.
	clientHS, raw, err := reflex.ReadClientHandshakeHTTPWithRaw(reader)
	if err != nil {
		return h.handleFallbackWithPrefix(ctx, reader, conn, raw)
	}
	return h.processHandshake(ctx, reader, conn, dispatcher, clientHS)
}

func (h *Handler) processHandshake(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, clientHS reflex.ClientHandshake) error {
	entry, ok := h.clientsByID[clientHS.UserID]
	if !ok {
		return h.handleFallback(ctx, reader, conn)
	}
	user := entry.user
	policyName := entry.policy

	// Basic replay protection (timestamp + nonce cache).
	if !isTimestampFresh(clientHS.Timestamp, 5*time.Minute) {
		return h.handleFallback(ctx, reader, conn)
	}
	if h.nonceCache != nil {
		if !h.nonceCache.Check(clientHS.UserID, clientHS.Nonce, time.Unix(clientHS.Timestamp, 0)) {
			return h.handleFallback(ctx, reader, conn)
		}
	}

	// Decrypt policy request (optional).
	psk := reflex.DerivePSK(clientHS.UserID)
	if len(clientHS.PolicyReq) > 0 {
		if pt, err := reflex.DecryptPolicy(psk, clientHS.PolicyReq); err == nil {
			if s := string(pt); s != "" {
				policyName = s
			}
		}
	}
	profile := reflex.CloneProfile(policyName)

	// Key exchange.
	serverPriv, serverPub, err := reflex.GenerateKeyPair()
	if err != nil {
		return err
	}
	shared, err := reflex.DeriveSharedSecret(serverPriv, clientHS.ClientPubKey)
	if err != nil {
		return err
	}
	sessionKey := reflex.DeriveSessionKey(shared, clientHS.Nonce[:])

	// Build policy grant (echo policy for now).
	policyGrant, _ := reflex.EncryptPolicy(psk, []byte(policyName))
	serverHS := reflex.ServerHandshake{ServerPubKey: serverPub, PolicyGrant: policyGrant}

	// Send an HTTP-like 200 OK response.
	resp := reflex.EncodeServerHandshakeHTTP(serverHS)
	if _, err := conn.Write(resp); err != nil {
		return err
	}

	// Enter encrypted session.
	return h.handleSession(ctx, reader, conn, dispatcher, sessionKey, user, profile)
}

func (h *Handler) handleSession(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, sessionKey [32]byte, user *protocol.MemoryUser, profile *reflex.TrafficProfile) error {
	_ = user

	sess, err := reflex.NewSession(sessionKey)
	if err != nil {
		return err
	}

	// First frame must contain destination request.
	frame, err := sess.ReadFrame(reader)
	if err != nil {
		return err
	}
	if frame.Type == reflex.FrameTypeClose {
		return nil
	}
	if frame.Type != reflex.FrameTypeData {
		return fmt.Errorf("reflex: expected request frame")
	}
	addr, port, initial, err := parseDestinationRequest(frame.Payload)
	if err != nil {
		return err
	}

	// Dial upstream.
	_ = dispatcher

	upstream, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", addr, port), 10*time.Second)
	if err != nil {
		// If dial fails, close gracefully.
		_ = sess.WriteFrame(conn, reflex.FrameTypeClose, nil)
		return err
	}
	defer func() { _ = upstream.Close() }()

	if len(initial) > 0 {
		_, _ = upstream.Write(initial)
	}

	// Bidirectional copy.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 2)
	var once sync.Once
	closeAll := func() {
		once.Do(func() {
			_ = upstream.Close()
			_ = conn.Close()
		})
	}

	// Client -> Upstream
	go func() {
		defer closeAll()
		for {
			f, err := sess.ReadFrame(reader)
			if err != nil {
				errCh <- err
				return
			}
			switch f.Type {
			case reflex.FrameTypeData:
				if len(f.Payload) > 0 {
					if _, err := upstream.Write(f.Payload); err != nil {
						errCh <- err
						return
					}
				}
			case reflex.FrameTypePadding, reflex.FrameTypeTiming:
				sess.HandleControlFrame(f, profile)
				continue
			case reflex.FrameTypeClose:
				errCh <- io.EOF
				return
			default:
				errCh <- fmt.Errorf("reflex: unknown frame type %d", f.Type)
				return
			}
		}
	}()

	// Upstream -> Client
	go func() {
		defer closeAll()
		buf := make([]byte, 32*1024)
		for {
			n, err := upstream.Read(buf)
			if n > 0 {
				if err := sess.WriteFrameWithMorphing(conn, reflex.FrameTypeData, buf[:n], profile); err != nil {
					errCh <- err
					return
				}
			}
			if err != nil {
				if errors.Is(err, io.EOF) {
					_ = sess.WriteFrame(conn, reflex.FrameTypeClose, nil)
					errCh <- io.EOF
					return
				}
				errCh <- err
				return
			}
			select {
			case <-ctx.Done():
				errCh <- ctx.Err()
				return
			default:
			}
		}
	}()

	// Wait for first error.
	err = <-errCh
	cancel()
	if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func parseDestinationRequest(b []byte) (addr string, port uint16, initial []byte, err error) {
	if len(b) < 1+2 {
		return "", 0, nil, fmt.Errorf("reflex: bad request")
	}
	addrLen := int(b[0])
	if addrLen <= 0 || len(b) < 1+addrLen+2 {
		return "", 0, nil, fmt.Errorf("reflex: bad address")
	}
	addr = string(b[1 : 1+addrLen])
	port = binary.BigEndian.Uint16(b[1+addrLen : 1+addrLen+2])
	initial = b[1+addrLen+2:]
	return addr, port, initial, nil
}

func isTimestampFresh(ts int64, maxSkew time.Duration) bool {
	if ts == 0 {
		return false
	}
	now := time.Now()
	t := time.Unix(ts, 0)
	d := now.Sub(t)
	if d < 0 {
		d = -d
	}
	return d <= maxSkew
}

// preloadedConn wraps a bufio.Reader so any peeked bytes are not lost.
type preloadedConn struct {
	*bufio.Reader
	stat.Connection
}

func (pc *preloadedConn) Read(b []byte) (int, error)  { return pc.Reader.Read(b) }
func (pc *preloadedConn) Write(b []byte) (int, error) { return pc.Connection.Write(b) }

func (h *Handler) handleFallback(ctx context.Context, reader *bufio.Reader, conn stat.Connection) error {
	return h.handleFallbackWithPrefix(ctx, reader, conn, nil)
}

// handleFallbackWithPrefix proxies the connection to the configured fallback server.
//
// prefix contains bytes that were already consumed from the client stream (e.g., by an attempted
// HTTP-handshake parser). We must forward prefix first, then continue streaming the remaining bytes.
func (h *Handler) handleFallbackWithPrefix(ctx context.Context, reader *bufio.Reader, conn stat.Connection, prefix []byte) error {
	_ = ctx

	if h.fallback == nil {
		return errors.New("reflex: no fallback configured")
	}

	// Wrap conn so buffered bytes in reader are not lost.
	wrapped := &preloadedConn{Reader: reader, Connection: conn}

	target, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", h.fallback.Dest), 3*time.Second)
	if err != nil {
		return err
	}
	defer func() { _ = target.Close() }()

	// 1) Send consumed bytes first (if any).
	if len(prefix) > 0 {
		if _, err := target.Write(prefix); err != nil {
			return err
		}
	}

	// 2) Full-duplex proxy.
	errCh := make(chan error, 2)
	var once sync.Once
	closeAll := func() {
		once.Do(func() {
			_ = target.Close()
			_ = conn.Close()
		})
	}

	// client -> target
	go func() {
		defer closeAll()
		_, err := io.Copy(target, wrapped)
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	// target -> client
	go func() {
		defer closeAll()
		_, err := io.Copy(wrapped, target)
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	err = <-errCh
	if err == nil || errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

// NonceCache tracks seen (userID, nonce) pairs to mitigate replay.
type NonceCache struct {
	mu    sync.Mutex
	seen  map[string]time.Time
	limit int
	ttl   time.Duration
}

func NewNonceCache(limit int, ttl time.Duration) *NonceCache {
	return &NonceCache{seen: make(map[string]time.Time), limit: limit, ttl: ttl}
}

func (c *NonceCache) key(userID [16]byte, nonce [16]byte) string {
	// 32 bytes -> string
	b := make([]byte, 32)
	copy(b[:16], userID[:])
	copy(b[16:], nonce[:])
	return string(b)
}

// Check returns true if the nonce is fresh (not seen recently), and records it.
func (c *NonceCache) Check(userID [16]byte, nonce [16]byte, t time.Time) bool {
	if c == nil {
		return true
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Clean old.
	if c.ttl > 0 {
		cut := time.Now().Add(-c.ttl)
		for k, ts := range c.seen {
			if ts.Before(cut) {
				delete(c.seen, k)
			}
		}
	}

	k := c.key(userID, nonce)
	if _, ok := c.seen[k]; ok {
		return false
	}
	c.seen[k] = t

	// Best-effort size bound.
	if c.limit > 0 && len(c.seen) > c.limit {
		toDelete := len(c.seen) - c.limit
		for key := range c.seen {
			delete(c.seen, key)
			toDelete--
			if toDelete <= 0 {
				break
			}
		}
	}
	return true
}

func init() {
	common.Must(common.RegisterConfig((*reflex.InboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*reflex.InboundConfig))
	}))
}

// New builds a Reflex inbound handler from config.
func New(ctx context.Context, config *reflex.InboundConfig) (proxy.Inbound, error) {
	h := &Handler{clientsByID: make(map[[16]byte]clientEntry)}

	for _, client := range config.Clients {
		idBytes, err := reflex.ParseUUID(client.Id)
		if err != nil {
			continue
		}

		u := &protocol.MemoryUser{
			Email:   client.Id,
			Level:   0,
			Account: &MemoryAccount{Id: client.Id},
		}

		h.clientsByID[idBytes] = clientEntry{
			user:   u,
			policy: client.Policy,
		}
	}

	if config.Fallback != nil {
		h.fallback = &FallbackConfig{Dest: config.Fallback.Dest}
	}

	// Replay cache: remember up to 2000 nonces for 10 minutes.
	h.nonceCache = NewNonceCache(2000, 10*time.Minute)

	_ = ctx
	return h, nil
}
