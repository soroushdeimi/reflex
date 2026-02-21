package inbound

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"time"

	"github.com/xtls/xray-core/common/errors"
	xtls "github.com/xtls/xray-core/transport/internet/tls"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/antireplay"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport/internet/stat"
	"google.golang.org/protobuf/proto"
)

// Handler implements the inbound side of the Reflex protocol.
// هندلر سمت ورودی (اینباند) پروتکل رفلکس.
type Handler struct {
	config       *reflex.InboundConfig
	clients      []*protocol.MemoryUser
	fallback     *FallbackConfig
	replayFilter antireplay.GeneralizedReplayFilter
}

// MemoryAccount holds user account information in memory.
type MemoryAccount struct {
	Id     string
	Policy string
}

func (a *MemoryAccount) Equals(account protocol.Account) bool {
	reflexAccount, ok := account.(*MemoryAccount)
	if !ok {
		return false
	}
	return a.Id == reflexAccount.Id && a.Policy == reflexAccount.Policy
}

func (a *MemoryAccount) ToProto() proto.Message {
	return &reflex.Account{
		Id: a.Id,
	}
}

type FallbackConfig struct {
	Dest uint32
}

func (h *Handler) Network() []net.Network {
	return []net.Network{net.Network_TCP, net.Network_UDP}
}

// Process handles the incoming connection and performs protocol detection and session management.
// مدیریت اتصال ورودی، تشخیص پروتکل و مدیریت نشست را انجام می‌دهد.
func (h *Handler) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	if h.config.Tls != nil && h.config.Tls.Enabled {
		tlsConfig := &tls.Config{
			NextProtos: []string{"h2", "http/1.1"},
		}

		if h.config.Tls.CertFile != "" && h.config.Tls.KeyFile != "" {
			cert, err := tls.LoadX509KeyPair(h.config.Tls.CertFile, h.config.Tls.KeyFile)
			if err != nil {
				return errors.New("failed to load certificate: ").Base(err)
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
		} else {
			return errors.New("TLS is enabled but cert_file or key_file is missing")
		}

		if len(h.config.Tls.EchKey) > 0 {
			keys, err := xtls.ConvertToGoECHKeys(h.config.Tls.EchKey)
			if err != nil {
				return errors.New("failed to convert ECH keys: ").Base(err)
			}
			tlsConfig.EncryptedClientHelloKeys = keys
		}

		tlsConn := tls.Server(conn, tlsConfig)
		// Set a handshake timeout
		conn.SetDeadline(time.Now().Add(time.Second * 10))
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			tlsConn.Close()
			return err
		}
		conn.SetDeadline(time.Time{})
		conn = tlsConn
	}

	reader := bufio.NewReader(conn)
	peeked, err := reader.Peek(64)
	if err != nil {
		return err
	}

	if h.IsReflexMagic(peeked) {
		return h.HandleReflexMagic(ctx, reader, conn, dispatcher)
	}

	if h.IsHTTPPostLike(peeked) {
		return h.HandleReflexHTTP(ctx, reader, conn, dispatcher)
	}

	return h.handleFallback(ctx, reader, conn)
}

func (h *Handler) IsReflexMagic(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	magic := binary.BigEndian.Uint32(data[0:4])
	return magic == reflex.ReflexMagic
}

func (h *Handler) IsHTTPPostLike(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	return string(data[0:4]) == "POST"
}

func (h *Handler) HandleReflexMagic(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher) error {
	// Skip magic number
	io.CopyN(io.Discard, reader, 4)

	var clientHS reflex.ClientHandshake
	if err := binary.Read(reader, binary.BigEndian, &clientHS); err != nil {
		return err
	}

	return h.processHandshake(ctx, reader, conn, dispatcher, clientHS)
}

func (h *Handler) HandleReflexHTTP(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher) error {
	line, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	if len(line) < 4 || line[0:4] != "POST" {
		return errors.New("invalid HTTP POST")
	}

	for {
		line, err := reader.ReadString('\n')
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}
	}

	var clientHS reflex.ClientHandshake
	if err := binary.Read(reader, binary.BigEndian, &clientHS); err != nil {
		return err
	}

	return h.processHandshake(ctx, reader, conn, dispatcher, clientHS)
}

func (h *Handler) processHandshake(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, clientHS reflex.ClientHandshake) error {
	// Validate timestamp (5 minutes tolerance)
	now := time.Now().Unix()
	delta := now - clientHS.Timestamp
	if delta < -300 || delta > 300 {
		return h.handleFallback(ctx, reader, conn)
	}

	serverPriv, serverPub, err := reflex.GenerateKeyPair()
	if err != nil {
		return err
	}

	// Check Replay
	if !h.replayFilter.Check(clientHS.Nonce[:]) {
		return h.handleFallback(ctx, reader, conn)
	}

	sharedKey := reflex.DeriveSharedKey(serverPriv, clientHS.PublicKey)
	c2s, s2c := reflex.DeriveSessionKeys(sharedKey, []byte("reflex-session"))

	user, err := h.AuthenticateUser(clientHS.UserID)
	if err != nil {
		return h.handleFallback(ctx, reader, conn)
	}

	serverHS := reflex.ServerHandshake{
		PublicKey: serverPub,
	}

	if err := binary.Write(conn, binary.BigEndian, &serverHS); err != nil {
		return err
	}

	return h.handleSession(ctx, reader, conn, dispatcher, c2s, s2c, user)
}

func (h *Handler) AuthenticateUser(userID [16]byte) (*protocol.MemoryUser, error) {
	u, err := uuid.FromBytes(userID[:])
	if err != nil {
		return nil, err
	}
	uStr := u.String()
	for _, user := range h.clients {
		if user.Account.(*MemoryAccount).Id == uStr {
			return user, nil
		}
	}
	return nil, errors.New("user not found")
}

func (h *Handler) handleFallback(ctx context.Context, reader *bufio.Reader, conn stat.Connection) error {
	if h.fallback == nil {
		return errors.New("no fallback configured")
	}

	target, err := net.Dial("tcp", net.TCPDestination(net.LocalHostIP, net.Port(h.fallback.Dest)).NetAddr())
	if err != nil {
		return err
	}
	defer target.Close()

	wrappedConn := &PreloadedConn{
		Reader:     reader,
		Connection: conn,
	}

	go io.Copy(target, wrappedConn)
	io.Copy(wrappedConn, target)

	return nil
}

type PreloadedConn struct {
	*bufio.Reader
	stat.Connection
}

func (pc *PreloadedConn) Read(b []byte) (int, error) {
	return pc.Reader.Read(b)
}

func (pc *PreloadedConn) Write(b []byte) (int, error) {
	return pc.Connection.Write(b)
}

func (h *Handler) handleSession(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, readKey, writeKey []byte, user *protocol.MemoryUser) error {
	session, err := reflex.NewSession(readKey, writeKey)
	if err != nil {
		return err
	}

	// Read the first DATA frame to get the destination
	frame, err := session.ReadFrame(reader)
	if err != nil {
		return err
	}

	if frame.Type != reflex.FrameTypeData {
		return errors.New("expected DATA frame")
	}

	// Parse destination from frame payload
	addrParser := protocol.NewAddressParser(
		protocol.AddressFamilyByte(0x01, net.AddressFamilyIPv4),
		protocol.AddressFamilyByte(0x02, net.AddressFamilyDomain),
		protocol.AddressFamilyByte(0x03, net.AddressFamilyIPv6),
	)

	payloadReader := bytes.NewReader(frame.Payload)

	// Read Network byte
	networkByte, err := payloadReader.ReadByte()
	if err != nil {
		return err
	}

	addr, port, err := addrParser.ReadAddressPort(nil, payloadReader)
	if err != nil {
		return err
	}

	network := net.Network_TCP
	if networkByte == reflex.NetworkUDP {
		network = net.Network_UDP
	}

	dest := net.Destination{
		Network: network,
		Address: addr,
		Port:    port,
	}
	link, err := dispatcher.Dispatch(ctx, dest)
	if err != nil {
		return err
	}

	// Send remaining data from the first frame to upstream
	remainingData := make([]byte, payloadReader.Len())
	payloadReader.Read(remainingData)
	if len(remainingData) > 0 {
		if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(remainingData)}); err != nil {
			return err
		}
	}

	// Bidirectional forwarding
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var profile *reflex.TrafficProfile
	if user != nil {
		account := user.Account.(*MemoryAccount)
		if account.Policy != "" {
			profile = reflex.Profiles[account.Policy]
		}
	}

	go func() {
		defer cancel()
		for {
			mb, err := link.Reader.ReadMultiBuffer()
			if err != nil {
				break
			}
			for _, b := range mb {
				var err error
				if profile != nil {
					err = session.WriteFrameWithMorphing(conn, reflex.FrameTypeData, b.Bytes(), profile)
				} else {
					err = session.WriteFrame(conn, reflex.FrameTypeData, b.Bytes())
				}
				if err != nil {
					b.Release()
					return
				}
				b.Release()
			}
		}
		session.WriteFrame(conn, reflex.FrameTypeClose, nil)
	}()

	for {
		frame, err := session.ReadFrame(reader)
		if err != nil {
			break
		}
		if frame.Type == reflex.FrameTypeClose {
			break
		}
		switch frame.Type {
		case reflex.FrameTypeData:
			if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(frame.Payload)}); err != nil {
				return err
			}
		case reflex.FrameTypePadding, reflex.FrameTypeTiming:
			session.HandleControlFrame(frame, profile)
		}
	}

	return nil
}

func init() {
	common.Must(common.RegisterConfig((*reflex.InboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*reflex.InboundConfig))
	}))
}

func New(ctx context.Context, config *reflex.InboundConfig) (proxy.Inbound, error) {
	handler := &Handler{
		config:       config,
		clients:      make([]*protocol.MemoryUser, 0),
		replayFilter: antireplay.NewBloomRing(),
	}

	for _, client := range config.Clients {
		handler.clients = append(handler.clients, &protocol.MemoryUser{
			Email: client.Id,
			Account: &MemoryAccount{
				Id:     client.Id,
				Policy: client.Policy,
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
