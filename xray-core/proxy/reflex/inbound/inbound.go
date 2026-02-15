package inbound

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	gonet "net"
	"sync"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport/internet/stat"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"google.golang.org/protobuf/proto"
)

const (
	ReflexMagic            = 0x5246584C // "REFX"
	ReflexMinHandshakeSize = 64
)

type ClientHandshake struct {
	PublicKey [32]byte
	UserID    [16]byte
	PolicyReq []byte // Encrypted with pre-shared key
	Timestamp int64
	Nonce     [16]byte
}

type ClientHandshakePacket struct {
	Magic     [4]byte
	Handshake ClientHandshake
}

type ServerHandshake struct {
	PublicKey   [32]byte
	PolicyGrant []byte
}

type Handler struct {
	clients  []*protocol.MemoryUser
	fallback *FallbackConfig
}

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
	return &reflex.Account{
		Id: a.Id,
	}
}

type FallbackConfig struct {
	Dest uint32
}

func init() {
	common.Must(common.RegisterConfig((*reflex.InboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*reflex.InboundConfig))
	}))
}

func New(ctx context.Context, config *reflex.InboundConfig) (proxy.Inbound, error) {
	handler := &Handler{
		clients: make([]*protocol.MemoryUser, 0),
	}

	for _, client := range config.Clients {
		handler.clients = append(handler.clients, &protocol.MemoryUser{
			Email:   client.Id,
			Account: &MemoryAccount{Id: client.Id},
		})
	}

	if config.Fallback != nil {
		handler.fallback = &FallbackConfig{
			Dest: config.Fallback.Dest,
		}
	}

	return handler, nil
}

func (h *Handler) Network() []net.Network {
	return []net.Network{net.Network_TCP}
}

func (h *Handler) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	reader := bufio.NewReader(conn)

	peeked, err := reader.Peek(ReflexMinHandshakeSize)
	if err != nil {
		return h.handleFallback(ctx, reader, conn)
	}

	if !h.isReflexHandshake(peeked) {
		return h.handleFallback(ctx, reader, conn)
	}

	if h.isReflexMagic(peeked) {
		return h.handleReflexMagic(reader, conn, dispatcher, ctx)
	}

	//magic := binary.BigEndian.Uint32(peeked[0:4])
	//if magic == ReflexMagic {
	//	return h.handleReflexMagic(reader, conn, dispatcher, ctx)
	//}

	// If not magic, send to fallback
	return h.handleFallback(ctx, reader, conn)
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

func (h *Handler) isReflexMagic(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	magic := binary.BigEndian.Uint32(data[0:4])
	return magic == ReflexMagic
}

func (h *Handler) isHTTPPostLike(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	return string(data[0:4]) == "POST"
}

type preloadedConn struct {
	*bufio.Reader
	stat.Connection
}

func (pc *preloadedConn) Read(b []byte) (int, error)  { return pc.Reader.Read(b) }
func (pc *preloadedConn) Write(b []byte) (int, error) { return pc.Connection.Write(b) }

func (h *Handler) handleFallback(ctx context.Context, reader *bufio.Reader, conn stat.Connection) error {
	if h.fallback == nil || h.fallback.Dest == 0 {
		return newError("no fallback configured")
	}

	wrappedConn := &preloadedConn{
		Reader:     reader,
		Connection: conn,
	}

	target, err := gonet.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", h.fallback.Dest))
	if err != nil {
		return newError("failed to dial fallback").Base(err)
	}
	defer target.Close()

	errCh := make(chan error, 2)

	go func() {
		_, e := io.Copy(target, wrappedConn)
		errCh <- e
	}()

	go func() {
		_, e := io.Copy(wrappedConn, target)
		errCh <- e
	}()

	return <-errCh
}

func (h *Handler) handleReflexMagic(reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, ctx context.Context) error {
	magicBuf := make([]byte, 4)
	if _, err := io.ReadFull(reader, magicBuf); err != nil {
		return newError("failed to read magic").Base(err)
	}

	var clientHS ClientHandshake

	if _, err := io.ReadFull(reader, clientHS.PublicKey[:]); err != nil {
		return newError("failed to read public key").Base(err)
	}
	if _, err := io.ReadFull(reader, clientHS.UserID[:]); err != nil {
		return newError("failed to read user ID").Base(err)
	}

	var timestamp int64
	if err := binary.Read(reader, binary.BigEndian, &timestamp); err != nil {
		return newError("failed to read timestamp").Base(err)
	}
	clientHS.Timestamp = timestamp

	if _, err := io.ReadFull(reader, clientHS.Nonce[:]); err != nil {
		return newError("failed to read nonce").Base(err)
	}

	return h.processHandshake(reader, conn, dispatcher, ctx, clientHS)
}

func (h *Handler) processHandshake(reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, ctx context.Context, clientHS ClientHandshake) error {
	serverPriv, serverPub, err := generateKeyPair()
	if err != nil {
		return newError("failed to generate keypair").Base(err)
	}
	_ = serverPub // Silence unused variable error

	sharedKey, err := deriveSharedKey(serverPriv, clientHS.PublicKey)
	if err != nil {
		return newError("failed to derive shared key").Base(err)
	}
	sessionKey := deriveSessionKey(sharedKey, []byte("reflex-session"))
	_ = sessionKey

	user, err := h.authenticateUserBytes(clientHS.UserID)
	if err != nil {
		return h.handleFallback(ctx, reader, conn)
	}

	// Fake HTTP 200
	response := []byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n")
	if _, err := conn.Write(response); err != nil {
		return newError("failed to write handshake response").Base(err)
	}

	if _, err := conn.Write(serverPub[:]); err != nil {
		return newError("failed to write server public key").Base(err)
	}

	return h.handleSession(ctx, reader, conn, dispatcher, sessionKey, user)
}

type upstreamLink struct {
	Reader buf.Reader
	Writer buf.Writer
}

func (h *Handler) handleSession(
	ctx context.Context,
	reader *bufio.Reader,
	conn stat.Connection,
	dispatcher routing.Dispatcher,
	sessionKey []byte,
	user *protocol.MemoryUser,
) error {
	sess, err := reflex.NewSession(sessionKey)
	if err != nil {
		return newError("failed to create session").Base(err)
	}

	var (
		once    sync.Once
		link    *upstreamLink
		destErr error
	)

	startDownlink := func(l *upstreamLink) {
		go func() {
			_ = h.pipeDownlink(ctx, sess, conn, l)
		}()
	}

	for {
		frame, err := sess.ReadFrame(reader)
		if err != nil {
			return newError("failed to read frame").Base(err)
		}

		switch frame.Type {
		case reflex.FrameTypeData:
			once.Do(func() {
				dest, rest, err := reflex.ParseDestFromPayload(frame.Payload)
				if err != nil {
					destErr = err
					return
				}

				dl, err := dispatcher.Dispatch(ctx, dest)
				if err != nil {
					destErr = err
					return
				}

				link = &upstreamLink{Reader: dl.Reader, Writer: dl.Writer}
				startDownlink(link)

				if len(rest) > 0 {
					b := buf.FromBytes(rest)
					_ = link.Writer.WriteMultiBuffer(buf.MultiBuffer{b})
				}
			})

			if destErr != nil {
				return newError("failed to init upstream").Base(destErr)
			}
			if link == nil {
				return newError("upstream link not initialized")
			}

			if sess.ReadNonce == 1 {
				continue
			}

			b := buf.FromBytes(frame.Payload)
			if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
				return newError("failed writing to upstream").Base(err)
			}
			continue

		case reflex.FrameTypePadding:
			continue

		case reflex.FrameTypeTiming:
			continue

		case reflex.FrameTypeClose:
			if link != nil {
				common.Interrupt(link.Writer)
			}
			common.Interrupt(conn)
			return nil

		default:
			return errors.New("unknown frame type")
		}
	}
}

func (h *Handler) pipeDownlink(
	ctx context.Context,
	sess *reflex.Session,
	conn stat.Connection,
	link *upstreamLink,
) error {
	defer common.Interrupt(conn)

	for {
		mb, err := link.Reader.ReadMultiBuffer()
		if err != nil {
			_ = sess.WriteFrame(conn, reflex.FrameTypeClose, nil)
			return err
		}

		for _, b := range mb {
			if b == nil {
				continue
			}
			data := b.Bytes()
			if len(data) > 0 {
				if err := sess.WriteFrame(conn, reflex.FrameTypeData, data); err != nil {
					b.Release()
					return err
				}
			}
			b.Release()
		}
	}
}

func generateKeyPair() ([32]byte, [32]byte, error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return [32]byte{}, [32]byte{}, err
	}

	pubBytes, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return [32]byte{}, [32]byte{}, err
	}

	var pub [32]byte
	copy(pub[:], pubBytes)
	return priv, pub, nil
}

func deriveSharedKey(priv [32]byte, peerPub [32]byte) ([32]byte, error) {
	sharedBytes, err := curve25519.X25519(priv[:], peerPub[:])
	if err != nil {
		return [32]byte{}, err
	}
	var shared [32]byte
	copy(shared[:], sharedBytes)
	return shared, nil
}

func deriveSessionKey(sharedKey [32]byte, salt []byte) []byte {
	hkdf := hkdf.New(sha256.New, sharedKey[:], salt, []byte("reflex-session"))
	sessionKey := make([]byte, 32)
	hkdf.Read(sessionKey)
	return sessionKey
}

func (h *Handler) authenticateUserBytes(userID [16]byte) (*protocol.MemoryUser, error) {
	for _, user := range h.clients {
		accountID := user.Account.(*MemoryAccount).Id
		parsedUUID, err := uuid.Parse(accountID)
		if err != nil {
			continue
		}
		if parsedUUID == uuid.UUID(userID) {
			return user, nil
		}
	}
	return nil, newError("user not found")
}

func newError(values ...interface{}) *errors.Error {
	return errors.New(values...)
}
