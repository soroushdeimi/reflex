// Package inbound implements the Reflex inbound handler.
package inbound

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func init() {
	common.Must(common.RegisterConfig((*reflex.InboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*reflex.InboundConfig))
	}))
}

// Handler is an inbound connection handler for the Reflex protocol.
type Handler struct {
	policyManager policy.Manager
	clients       []*protocol.MemoryUser
	clientEntries []*reflex.ClientEntry
	fallback      *reflex.Fallback
	nonceTracker  *reflex.NonceTracker
	tlsConfig     *tls.Config
}

// New creates a new Reflex inbound handler.
func New(ctx context.Context, config *reflex.InboundConfig) (*Handler, error) {
	v := core.MustFromContext(ctx)
	handler := &Handler{
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
		clients:       make([]*protocol.MemoryUser, 0, len(config.GetClients())),
		clientEntries: make([]*reflex.ClientEntry, 0, len(config.GetClients())),
		nonceTracker:  reflex.NewNonceTracker(10000),
	}

	for _, client := range config.GetClients() {
		account := &reflex.Account{Id: client.GetId()}
		memAccount, err := account.AsAccount()
		if err != nil {
			return nil, errors.New("failed to create reflex account").Base(err).AtError()
		}
		handler.clients = append(handler.clients, &protocol.MemoryUser{
			Email:   client.GetId(),
			Account: memAccount,
		})
		handler.clientEntries = append(handler.clientEntries, &reflex.ClientEntry{
			ID:     client.GetId(),
			Policy: client.GetPolicy(),
		})
	}

	if config.GetFallback() != nil {
		handler.fallback = config.GetFallback()
	}

	if ech := config.GetEch(); ech != nil && ech.GetEnabled() {
		tlsCfg, err := reflex.BuildServerTLSConfig(ech)
		if err != nil {
			return nil, errors.New("failed to build TLS+ECH config").Base(err).AtError()
		}
		handler.tlsConfig = tlsCfg
	}

	return handler, nil
}

func (h *Handler) Network() []net.Network {
	return []net.Network{net.Network_TCP}
}

// preloadedConn wraps a bufio.Reader with the original connection so that
// peeked bytes are transparently re-read when forwarding to a fallback.
type preloadedConn struct {
	reader *bufio.Reader
	stat.Connection
}

func (pc *preloadedConn) Read(b []byte) (int, error) {
	return pc.reader.Read(b)
}

func (pc *preloadedConn) Write(b []byte) (int, error) {
	return pc.Connection.Write(b)
}

// Process implements proxy.Inbound.Process().
func (h *Handler) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	sessionPolicy := h.policyManager.ForLevel(0)

	if err := conn.SetReadDeadline(time.Now().Add(sessionPolicy.Timeouts.Handshake)); err != nil {
		return errors.New("unable to set read deadline").Base(err).AtWarning()
	}

	// If TLS+ECH is configured, wrap the raw TCP connection in a TLS server
	// before proceeding with Reflex protocol detection.
	if h.tlsConfig != nil {
		tlsConn := tls.Server(conn, h.tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return errors.New("TLS+ECH handshake failed").Base(err).AtWarning()
		}
		conn = stat.Connection(tlsConn)
	}

	reader := bufio.NewReaderSize(conn, 4096)

	peeked, err := reader.Peek(4)
	if err != nil {
		if h.fallback != nil {
			return h.handleFallback(ctx, sessionPolicy, reader, conn)
		}
		return errors.New("failed to peek initial bytes").Base(err).AtWarning()
	}

	magic := binary.BigEndian.Uint32(peeked[0:4])
	if magic != reflex.ReflexMagic {
		if h.fallback != nil {
			return h.handleFallback(ctx, sessionPolicy, reader, conn)
		}
		return errors.New("not a Reflex handshake and no fallback configured").AtWarning()
	}

	hsData := make([]byte, reflex.HandshakeHeaderSize)
	if _, err := io.ReadFull(reader, hsData); err != nil {
		return errors.New("failed to read handshake data").Base(err).AtWarning()
	}

	clientHS, err := reflex.UnmarshalClientHandshake(hsData)
	if err != nil {
		if h.fallback != nil {
			return h.handleFallback(ctx, sessionPolicy, reader, conn)
		}
		return errors.New("invalid handshake").Base(err).AtWarning()
	}

	if !reflex.ValidateTimestamp(clientHS.Timestamp) {
		return errors.New("handshake timestamp out of range").AtWarning()
	}

	nonceVal := binary.BigEndian.Uint64(clientHS.Nonce[0:8])
	if !h.nonceTracker.Check(nonceVal) {
		return errors.New("replay detected: duplicate nonce").AtWarning()
	}

	clientEntry := reflex.AuthenticateUser(clientHS.UserID, h.clientEntries)
	if clientEntry == nil {
		if h.fallback != nil {
			return h.handleFallback(ctx, sessionPolicy, reader, conn)
		}
		return errors.New("authentication failed: unknown UUID").AtWarning()
	}

	serverPrivKey, serverPubKey, err := reflex.GenerateKeyPair()
	if err != nil {
		return errors.New("failed to generate server keypair").Base(err).AtError()
	}

	sharedSecret, err := reflex.DeriveSharedSecret(serverPrivKey, clientHS.PublicKey)
	if err != nil {
		return errors.New("key exchange failed").Base(err).AtError()
	}
	sessionKey, err := reflex.DeriveSessionKey(sharedSecret, clientHS.Nonce[:])
	if err != nil {
		return errors.New("session key derivation failed").Base(err).AtError()
	}

	serverHS := &reflex.ServerHandshake{PublicKey: serverPubKey}
	if _, err := conn.Write(reflex.MarshalServerHandshake(serverHS)); err != nil {
		return errors.New("failed to send server handshake").Base(err).AtWarning()
	}

	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return errors.New("unable to clear read deadline").Base(err).AtWarning()
	}

	return h.handleSession(ctx, reader, conn, dispatcher, sessionKey, clientEntry)
}

// handleSession processes encrypted frames after a successful handshake.
func (h *Handler) handleSession(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, sessionKey []byte, client *reflex.ClientEntry) error {
	sess, err := reflex.NewSession(sessionKey)
	if err != nil {
		return errors.New("failed to create session").Base(err).AtError()
	}

	morph := reflex.NewTrafficMorph(client.Policy)

	sessionPolicy := h.policyManager.ForLevel(0)

	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   conn.RemoteAddr(),
		To:     net.LocalHostIP,
		Status: log.AccessAccepted,
		Email:  client.ID,
	})

	firstFrame, err := sess.ReadFrame(reader)
	if err != nil {
		return errors.New("failed to read first frame").Base(err).AtWarning()
	}
	if firstFrame.Type != reflex.FrameTypeData || len(firstFrame.Payload) == 0 {
		return errors.New("expected DATA frame with destination").AtWarning()
	}

	dest, payload, err := parseDestination(firstFrame.Payload)
	if err != nil {
		return errors.New("failed to parse destination").Base(err).AtWarning()
	}

	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, cancel, sessionPolicy.Timeouts.ConnectionIdle)

	link, err := dispatcher.Dispatch(ctx, dest)
	if err != nil {
		return errors.New("failed to dispatch").Base(err).AtWarning()
	}

	requestDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)

		if len(payload) > 0 {
			mb := buf.MultiBuffer{buf.FromBytes(payload)}
			if err := link.Writer.WriteMultiBuffer(mb); err != nil {
				return errors.New("failed to write first payload").Base(err).AtWarning()
			}
		}

		for {
			frame, err := sess.ReadFrame(reader)
			if err != nil {
				return err
			}
			switch frame.Type {
			case reflex.FrameTypeData:
				mb := buf.MultiBuffer{buf.FromBytes(frame.Payload)}
				if err := link.Writer.WriteMultiBuffer(mb); err != nil {
					return err
				}
				timer.Update()
			case reflex.FrameTypePadding, reflex.FrameTypeTiming:
				if morph != nil && morph.Profile != nil {
					reflex.HandleControlFrame(frame, morph.Profile)
				}
				continue
			case reflex.FrameTypeClose:
				return nil
			default:
				return errors.New("unknown frame type")
			}
		}
	}

	responseDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)

		for {
			mb, err := link.Reader.ReadMultiBuffer()
			if err != nil {
				return err
			}
			for _, b := range mb {
				data := b.Bytes()
				if morph != nil && morph.Enabled {
					if err := morph.MorphWrite(sess, conn, data); err != nil {
						b.Release()
						return errors.New("failed to write morphed response").Base(err).AtInfo()
					}
				} else {
					if err := sess.WriteFrame(conn, reflex.FrameTypeData, data); err != nil {
						b.Release()
						return errors.New("failed to write response frame").Base(err).AtInfo()
					}
				}
				b.Release()
			}
			timer.Update()
		}
	}

	responseDoneAndCloseWriter := task.OnSuccess(responseDone, task.Close(link.Writer))
	if err := task.Run(ctx, requestDone, responseDoneAndCloseWriter); err != nil {
		_ = common.Interrupt(link.Reader)
		_ = common.Interrupt(link.Writer)
		return errors.New("connection ends").Base(err).AtInfo()
	}

	return nil
}

// parseDestination extracts the target address from the first DATA frame payload.
// Format: [addrType(1)] [addr(variable)] [port(2)] [remaining payload...]
// addrType: 1=IPv4(4 bytes), 2=domain(1 byte len + domain), 3=IPv6(16 bytes)
func parseDestination(data []byte) (net.Destination, []byte, error) {
	if len(data) < 4 {
		return net.Destination{}, nil, errors.New("destination data too short")
	}
	addrType := data[0]
	idx := 1
	var addr net.Address

	switch addrType {
	case 1: // IPv4
		if len(data) < idx+4+2 {
			return net.Destination{}, nil, errors.New("insufficient data for IPv4")
		}
		addr = net.IPAddress(data[idx : idx+4])
		idx += 4
	case 2: // Domain
		if len(data) < idx+1 {
			return net.Destination{}, nil, errors.New("insufficient data for domain length")
		}
		domainLen := int(data[idx])
		idx++
		if len(data) < idx+domainLen+2 {
			return net.Destination{}, nil, errors.New("insufficient data for domain")
		}
		addr = net.DomainAddress(string(data[idx : idx+domainLen]))
		idx += domainLen
	case 3: // IPv6
		if len(data) < idx+16+2 {
			return net.Destination{}, nil, errors.New("insufficient data for IPv6")
		}
		addr = net.IPAddress(data[idx : idx+16])
		idx += 16
	default:
		return net.Destination{}, nil, errors.New("unsupported address type")
	}

	port := net.Port(binary.BigEndian.Uint16(data[idx : idx+2]))
	idx += 2

	remaining := data[idx:]
	return net.TCPDestination(addr, port), remaining, nil
}

// handleFallback forwards the connection (including peeked bytes) to the
// fallback destination using a preloadedConn wrapper around bufio.Reader.
func (h *Handler) handleFallback(ctx context.Context, sessionPolicy policy.Session, reader *bufio.Reader, conn stat.Connection) error {
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		errors.LogWarningInner(ctx, err, "unable to clear read deadline")
	}

	dest := net.TCPDestination(net.LocalHostIP, net.Port(h.fallback.GetDest()))
	errors.LogInfo(ctx, "falling back to ", dest)

	fbConn, err := internet.DialSystem(ctx, dest, nil)
	if err != nil {
		return errors.New("failed to connect to fallback destination").Base(err).AtWarning()
	}
	defer func() { _ = fbConn.Close() }()

	wrapped := &preloadedConn{reader: reader, Connection: conn}

	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{
		Target: dest,
	}})

	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, cancel, sessionPolicy.Timeouts.ConnectionIdle)

	postRequest := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)
		_, err := io.Copy(fbConn, wrapped)
		return err
	}

	getResponse := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)
		_, err := io.Copy(conn, fbConn)
		return err
	}

	if err := task.Run(ctx, postRequest, getResponse); err != nil {
		return errors.New("fallback ends").Base(err).AtInfo()
	}
	return nil
}
