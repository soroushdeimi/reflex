package inbound

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	stdnet "net"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport/internet/stat"
	"google.golang.org/protobuf/proto"
)

const ReflexMinHandshakeSize = 64

type Handler struct {
	clients      []*protocol.MemoryUser
	userPolicies map[string]string
	fallback     *FallbackConfig
	tlsConfig    *tls.Config
}

type MemoryAccount struct {
	Id string
}

type FallbackConfig struct {
	Dest uint32
}

type preloadedConn struct {
	*bufio.Reader
	stat.Connection
}

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

func (pc *preloadedConn) Read(b []byte) (int, error) {
	return pc.Reader.Read(b)
}

func (pc *preloadedConn) Write(b []byte) (int, error) {
	return pc.Connection.Write(b)
}

type tlsConnWrapper struct {
	*tls.Conn
	originalConn stat.Connection
}

func (w *tlsConnWrapper) Read(b []byte) (int, error) {
	return w.Conn.Read(b)
}

func (w *tlsConnWrapper) Write(b []byte) (int, error) {
	return w.Conn.Write(b)
}

func (w *tlsConnWrapper) Close() error {
	return w.Conn.Close()
}

func (w *tlsConnWrapper) RemoteAddr() stdnet.Addr {
	return w.Conn.RemoteAddr()
}

func (w *tlsConnWrapper) LocalAddr() stdnet.Addr {
	return w.Conn.LocalAddr()
}

func (w *tlsConnWrapper) SetDeadline(t time.Time) error {
	return w.Conn.SetDeadline(t)
}

func (w *tlsConnWrapper) SetReadDeadline(t time.Time) error {
	return w.Conn.SetReadDeadline(t)
}

func (w *tlsConnWrapper) SetWriteDeadline(t time.Time) error {
	return w.Conn.SetWriteDeadline(t)
}

func (h *Handler) Network() []net.Network {
	return []net.Network{net.Network_TCP, net.Network_UDP}
}

func (h *Handler) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	if h.tlsConfig != nil {
		tlsConn := tls.Server(conn, h.tlsConfig)
		if err := tlsConn.Handshake(); err != nil {
			return err
		}
		wrappedConn := &tlsConnWrapper{
			Conn:         tlsConn,
			originalConn: conn,
		}
		conn = wrappedConn
	}

	reader := bufio.NewReader(conn)

	peeked, err := reader.Peek(ReflexMinHandshakeSize)
	if err != nil {
		return err
	}

	if h.isReflexHandshake(peeked) {
		if len(peeked) >= 4 {
			magic := binary.BigEndian.Uint32(peeked[0:4])
			if magic == reflex.ReflexMagic {
				return h.handleReflexMagic(reader, conn, dispatcher, ctx)
			}
		}
		if h.isHTTPPostLike(peeked) {
			return h.handleReflexHTTP(reader, conn, dispatcher, ctx)
		}
		return h.handleFallback(ctx, reader, conn)
	} else {
		return h.handleFallback(ctx, reader, conn)
	}
}

func (h *Handler) isReflexMagic(data []byte) bool {
	if len(data) < 4 {
		return false
	}

	magic := binary.BigEndian.Uint32(data[0:4])
	return magic == reflex.ReflexMagic
}

func (h *Handler) isHTTPPostLike(data []byte) bool {
	if len(data) < 4 {
		return false
	}

	if string(data[0:4]) != "POST" {
		return false
	}

	return true
}

func (h *Handler) isReflexHandshake(data []byte) bool {
	if h.isReflexMagic(data) {
		return true
	}

	if h.isHTTPPostLike(data) {
		return true
	}

	return false
}

func (h *Handler) handleReflexMagic(reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, ctx context.Context) error {
	magic := make([]byte, 4)
	if _, err := io.ReadFull(reader, magic); err != nil {
		return err
	}

	var packet reflex.ClientHandshakePacket
	copy(packet.Magic[:], magic)

	if _, err := io.ReadFull(reader, packet.Handshake.PublicKey[:]); err != nil {
		return err
	}

	if _, err := io.ReadFull(reader, packet.Handshake.UserID[:]); err != nil {
		return err
	}

	policyReqLenBytes := make([]byte, 2)
	if _, err := io.ReadFull(reader, policyReqLenBytes); err != nil {
		return err
	}
	policyReqLen := binary.BigEndian.Uint16(policyReqLenBytes)

	packet.Handshake.PolicyReq = make([]byte, policyReqLen)
	if policyReqLen > 0 {
		if _, err := io.ReadFull(reader, packet.Handshake.PolicyReq); err != nil {
			return err
		}
	}

	timestampBytes := make([]byte, 8)
	if _, err := io.ReadFull(reader, timestampBytes); err != nil {
		return err
	}
	packet.Handshake.Timestamp = int64(binary.BigEndian.Uint64(timestampBytes))

	if _, err := io.ReadFull(reader, packet.Handshake.Nonce[:]); err != nil {
		return err
	}

	return h.processHandshake(reader, conn, dispatcher, ctx, packet.Handshake)
}

func (h *Handler) handleReflexHTTP(reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, ctx context.Context) error {
	var clientHS reflex.ClientHandshake
	return h.processHandshake(reader, conn, dispatcher, ctx, clientHS)
}

func (h *Handler) processHandshake(reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, ctx context.Context, clientHS reflex.ClientHandshake) error {
	serverPrivateKey, serverPublicKey, err := reflex.GenerateKeyPair()
	if err != nil {
		return h.handleError(ctx, conn, err, 500)
	}

	sharedKey := reflex.DeriveSharedKey(serverPrivateKey, clientHS.PublicKey)
	sessionKey := reflex.DeriveSessionKey(sharedKey, []byte("reflex-session"))

	user, err := h.authenticateUser(clientHS.UserID)
	if err != nil {
		return h.handleFallback(ctx, reader, conn)
	}

	_ = reflex.ServerHandshake{
		PublicKey:   serverPublicKey,
		PolicyGrant: []byte{},
	}

	response := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"ok\"}"
	if _, err := conn.Write([]byte(response)); err != nil {
		return err
	}

	return h.handleSession(ctx, reader, conn, dispatcher, sessionKey, user)
}

func (h *Handler) handleFallback(ctx context.Context, reader *bufio.Reader, conn stat.Connection) error {
	if h.fallback == nil {
		return errors.New("no fallback configured")
	}

	wrappedConn := &preloadedConn{
		Reader:     reader,
		Connection: conn,
	}

	target, err := stdnet.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", h.fallback.Dest))
	if err != nil {
		return err
	}
	defer target.Close()

	go io.Copy(target, wrappedConn)
	io.Copy(wrappedConn, target)

	return nil
}

func (h *Handler) authenticateUser(userID [16]byte) (*protocol.MemoryUser, error) {
	userUUID, err := uuid.ParseBytes(userID[:])
	if err != nil {
		return nil, errors.New("invalid user ID format")
	}
	userIDStr := userUUID.String()

	for _, user := range h.clients {
		if user.Account.(*MemoryAccount).Id == userIDStr {
			return user, nil
		}
	}
	return nil, errors.New("user not found")
}

func (h *Handler) sendErrorResponse(conn stat.Connection, statusCode int, message string) {
	response := fmt.Sprintf("HTTP/1.1 %d %s\r\nConnection: close\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s",
		statusCode, message, len(message), message)
	conn.Write([]byte(response))
}

func (h *Handler) handleError(ctx context.Context, conn stat.Connection, err error, statusCode int) error {
	if statusCode == 0 {
		statusCode = 403
	}

	errorMsg := "Forbidden"
	if statusCode == 400 {
		errorMsg = "Bad Request"
	} else if statusCode == 401 {
		errorMsg = "Unauthorized"
	} else if statusCode == 500 {
		errorMsg = "Internal Server Error"
	}

	h.sendErrorResponse(conn, statusCode, errorMsg)

	if err != nil && errors.Cause(err) != io.EOF {
		log.Record(&log.AccessMessage{
			From:   conn.RemoteAddr(),
			To:     "",
			Status: log.AccessRejected,
			Reason: err,
		})
		err = errors.New("reflex handshake failed").Base(err).AtInfo()
		errors.LogInfo(ctx, err.Error())
	}

	return err
}

func (h *Handler) handleSession(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, sessionKey []byte, user *protocol.MemoryUser) error {
	session, err := reflex.NewSession(sessionKey)
	if err != nil {
		return err
	}

	account := user.Account.(*MemoryAccount)
	profileName := h.getProfileForUser(account.Id)
	if profileName != "" {
		session.SetProfile(profileName)
	} else {
		session.StartYouTubeMorphing()
	}

	for {
		frame, err := session.ReadFrame(reader)
		if err != nil {
			return err
		}

		switch frame.Type {
		case reflex.FrameTypeData:
			err := h.handleData(ctx, frame.Payload, conn, dispatcher, session, user)
			if err != nil {
				return err
			}
			continue

		case reflex.FrameTypePadding:
			if session.GetProfile() != nil {
				session.HandleControlFrame(frame, session.GetProfile())
			}
			continue

		case reflex.FrameTypeTiming:
			if session.GetProfile() != nil {
				session.HandleControlFrame(frame, session.GetProfile())
			}
			continue

		case reflex.FrameTypeClose:
			return nil

		default:
			return errors.New("unknown frame type")
		}
	}
}

func (h *Handler) handleData(ctx context.Context, data []byte, conn stat.Connection, dispatcher routing.Dispatcher, session *reflex.Session, user *protocol.MemoryUser) error {
	dest := net.TCPDestination(net.ParseAddress("example.com"), net.Port(80))

	link, err := dispatcher.Dispatch(ctx, dest)
	if err != nil {
		return err
	}

	buffer := buf.FromBytes(data)
	if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{buffer}); err != nil {
		return err
	}

	go func() {
		// I saw this in proxy/http/server.go:254, so I'm doing it here too
		defer common.Close(link.Writer)
		for {
			mb, err := link.Reader.ReadMultiBuffer()
			if err != nil {
				return
			}
			for _, b := range mb {
				if err := session.WriteFrameWithMorphingIfEnabled(conn, reflex.FrameTypeData, b.Bytes()); err != nil {
					b.Release()
					return
				}
				b.Release()
			}
		}
	}()

	return nil
}

func init() {
	common.Must(common.RegisterConfig((*reflex.InboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*reflex.InboundConfig))
	}))
}

func generateECHKey() ([]byte, *ecdh.PrivateKey, error) {
	curve := ecdh.X25519()
	priv := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, priv)
	if err != nil {
		return nil, nil, err
	}

	privateKey, err := curve.NewPrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}

	return priv, privateKey, nil
}

func createECHConfig(privateKey *ecdh.PrivateKey, publicSNI string) ([]byte, error) {
	publicKeyBytes := privateKey.PublicKey().Bytes()

	echConfig := make([]byte, 0, 100)
	echConfig = append(echConfig, 0xfe, 0x0d)
	echConfig = append(echConfig, 0x00, 0x00)

	configID := byte(0)
	echConfig = append(echConfig, configID)

	kemID := []byte{0x00, 0x20}
	echConfig = append(echConfig, kemID...)

	publicKeyLen := uint16(len(publicKeyBytes))
	echConfig = append(echConfig, byte(publicKeyLen>>8), byte(publicKeyLen))
	echConfig = append(echConfig, publicKeyBytes...)

	cipherSuite := []byte{0x00, 0x01, 0x00, 0x01}
	echConfig = append(echConfig, cipherSuite...)

	maxNameLen := uint8(255)
	echConfig = append(echConfig, maxNameLen)

	publicNameLen := uint8(len(publicSNI))
	echConfig = append(echConfig, publicNameLen)
	echConfig = append(echConfig, []byte(publicSNI)...)

	extensionsLen := uint16(0)
	echConfig = append(echConfig, byte(extensionsLen>>8), byte(extensionsLen))

	configLen := uint16(len(echConfig) - 4)
	echConfig[2] = byte(configLen >> 8)
	echConfig[3] = byte(configLen)

	return echConfig, nil
}

func setupTLSWithECH(publicSNI string) (*tls.Config, error) {
	echPrivateKeyBytes, echPrivateKey, err := generateECHKey()
	if err != nil {
		return nil, err
	}

	echConfig, err := createECHConfig(echPrivateKey, publicSNI)
	if err != nil {
		return nil, err
	}

	config := &tls.Config{
		EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{
			{
				Config:     echConfig,
				PrivateKey: echPrivateKeyBytes,
			},
		},
		ServerName: publicSNI,
		MinVersion: tls.VersionTLS13,
	}
	return config, nil
}

func (h *Handler) getProfileForUser(userID string) string {
	if h.userPolicies != nil {
		if policy, ok := h.userPolicies[userID]; ok {
			return h.mapPolicyToProfile(policy)
		}
	}
	return ""
}

func (h *Handler) mapPolicyToProfile(policy string) string {
	switch policy {
	case "mimic-youtube", "youtube":
		return "youtube"
	case "mimic-zoom", "zoom":
		return "zoom"
	case "mimic-http2-api", "http2-api", "http2":
		return "http2-api"
	default:
		return ""
	}
}

func New(ctx context.Context, config *reflex.InboundConfig) (proxy.Inbound, error) {
	handler := &Handler{
		clients:      make([]*protocol.MemoryUser, 0),
		userPolicies: make(map[string]string),
	}

	for _, client := range config.Clients {
		handler.clients = append(handler.clients, &protocol.MemoryUser{
			Email:   client.Id,
			Account: &MemoryAccount{Id: client.Id},
		})
		if client.Policy != "" {
			handler.userPolicies[client.Id] = client.Policy
		}
	}

	if config.Fallback != nil {
		handler.fallback = &FallbackConfig{
			Dest: config.Fallback.Dest,
		}
	}

	tlsConfig, err := setupTLSWithECH("cloudflare.com")
	if err == nil {
		handler.tlsConfig = tlsConfig
	}

	return handler, nil
}

func handleQUICConnection(ctx context.Context, conn *quic.Conn, h *Handler, dispatcher routing.Dispatcher) error {
	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		return err
	}

	streamConn := &reflex.QuicStreamConn{
		Stream: stream,
		Conn:   conn,
	}

	return h.Process(ctx, net.Network_TCP, streamConn, dispatcher)
}
