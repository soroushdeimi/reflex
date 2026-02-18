package inbound

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	gonet "net"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport/internet" 
	"github.com/xtls/xray-core/transport/internet/stat"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"google.golang.org/protobuf/proto"
)

const (
	ReflexMagic            = 0x5246584C 
	ReflexMinHandshakeSize = 72
)

// --- Helper Structs ---

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

type Handler struct {
	sync.RWMutex
	clients   []*protocol.MemoryUser
	fallback  *reflex.Fallback
	serverKey [32]byte
}

func init() {
	common.Must(common.RegisterConfig((*reflex.InboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*reflex.InboundConfig))
	}))
}

func New(ctx context.Context, config *reflex.InboundConfig) (proxy.Inbound, error) {
	h := &Handler{
		clients: make([]*protocol.MemoryUser, 0),
		fallback: config.Fallback,
	}

	for _, client := range config.Clients {
		h.clients = append(h.clients, &protocol.MemoryUser{
			Account: &MemoryAccount{Id: client.Id},
		})
	}

	priv, _, err := generateKeyPair()
	if err != nil {
		return nil, newError("failed to generate server key").Base(err)
	}
	h.serverKey = priv

	return h, nil
}

func (h *Handler) Network() []net.Network {
	return []net.Network{net.Network_TCP}
}

func (h *Handler) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	reader := bufio.NewReader(conn)
	peeked, err := reader.Peek(4)
	if err != nil {
		return h.handleFallback(ctx, conn)
	}

	if h.isReflexMagic(peeked) {
		_, _ = reader.Discard(4)
		session, err := h.ProcessHandshake(conn, reader)
		if err != nil {
			return err
		}
		return h.handleSession(ctx, conn, session, dispatcher)
	}

	return h.handleFallback(ctx, conn)
}

func (h *Handler) ProcessHandshake(conn gonet.Conn, reader io.Reader) (*reflex.Session, error) {
	hsBuffer := make([]byte, 72)
	if _, err := io.ReadFull(reader, hsBuffer); err != nil {
		return nil, newError("failed to read handshake body").Base(err)
	}

	var clientPubKey [32]byte
	copy(clientPubKey[:], hsBuffer[0:32])
	var userID [16]byte
	copy(userID[:], hsBuffer[32:48])
	clientTime := int64(binary.BigEndian.Uint64(hsBuffer[48:56]))
	nonce := hsBuffer[56:72]

	if delta := time.Now().Unix() - clientTime; delta < -30 || delta > 30 {
		return nil, newError("handshake expired or replay detected")
	}

	if _, err := h.authenticateUserBytes(userID); err != nil {
		return nil, err
	}

	sharedKey, err := deriveSharedKey(h.serverKey, clientPubKey)
	if err != nil {
		return nil, err
	}

	sessionKey, err := deriveSessionKey(sharedKey, nonce, []byte("reflex-session-v1"))
	if err != nil {
		return nil, err
	}

	serverPub, _ := curve25519.X25519(h.serverKey[:], curve25519.Basepoint)
	if _, err := conn.Write(serverPub); err != nil {
		return nil, err
	}

	return reflex.NewSession(sessionKey)
}

func (h *Handler) handleSession(ctx context.Context, conn gonet.Conn, session *reflex.Session, dispatcher routing.Dispatcher) error {
	defer func() { _ = conn.Close() }()

	firstFrame, err := session.ReadFrame(conn)
	if err != nil {
		return err
	}

	dest, rest, err := reflex.ParseDestFromPayload(firstFrame.Payload)
	if err != nil {
		return err
	}

	link, err := dispatcher.Dispatch(ctx, dest)
	if err != nil {
		return err
	}

	if len(rest) > 0 {
		_ = link.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(rest)})
	}

	go h.pipeUplink(session, conn, link.Writer)
	return h.pipeDownlink(conn, session, link.Reader)
}

func (h *Handler) pipeUplink(session *reflex.Session, conn io.Reader, writer buf.Writer) {
	for {
		frame, err := session.ReadFrame(conn)
		if err != nil {
			return
		}
		if frame.Type == reflex.FrameTypeData {
			_ = writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(frame.Payload)})
		}
	}
}

func (h *Handler) pipeDownlink(conn io.Writer, sess *reflex.Session, reader buf.Reader) error {
	for {
		mb, err := reader.ReadMultiBuffer()
		if err != nil {
			return err
		}
		for _, b := range mb {
			if b == nil { continue }
			if err := sess.WriteFrame(conn, reflex.FrameTypeData, b.Bytes()); err != nil {
				b.Release()
				return err
			}
			b.Release()
		}
	}
}

// handleFallback establishes a connection to the configured fallback server.
func (h *Handler) handleFallback(ctx context.Context, conn stat.Connection) error {
	defer func() { _ = conn.Close() }()
	if h.fallback == nil || h.fallback.Dest == 0 {
		return newError("no fallback configured")
	}

	dest := net.TCPDestination(net.LocalHostIP, net.Port(h.fallback.Dest))
	// Passing nil as the third argument uses the default transport settings for the destination.
	fConn, err := internet.Dial(ctx, dest, nil)
	if err != nil {
		return newError("fallback unreachable").Base(err)
	}
	_ = fConn.Close()
	return nil
}

func (h *Handler) isReflexMagic(data []byte) bool {
	return len(data) >= 4 && binary.BigEndian.Uint32(data) == ReflexMagic
}

// isHTTPPostLike identifies probing traffic for the fallback logic.
func (h *Handler) isHTTPPostLike(data []byte) bool {
	if len(data) < 4 { return false }
	return string(data[0:4]) == "POST" || string(data[0:3]) == "GET"
}

func (h *Handler) authenticateUserBytes(userID [16]byte) (*protocol.MemoryUser, error) {
	parsedInput, err := uuid.FromBytes(userID[:])
	if err != nil {
		return nil, err
	}
	for _, user := range h.clients {
		account := user.Account.(*MemoryAccount)
		storedUUID, _ := uuid.Parse(account.Id)
		if parsedInput == storedUUID {
			return user, nil
		}
	}
	return nil, newError("user not found")
}

// --- Cryptography Helpers ---

func generateKeyPair() ([32]byte, [32]byte, error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return priv, priv, err
	}
	pub, _ := curve25519.X25519(priv[:], curve25519.Basepoint)
	var pub32 [32]byte
	copy(pub32[:], pub)
	return priv, pub32, nil
}

func deriveSharedKey(priv [32]byte, peerPub [32]byte) ([32]byte, error) {
	shared, err := curve25519.X25519(priv[:], peerPub[:])
	var res [32]byte
	copy(res[:], shared)
	return res, err
}

func deriveSessionKey(sharedKey [32]byte, salt []byte, info []byte) ([]byte, error) {
	// HKDF-SHA256 Implementation
	kdf := hkdf.New(sha256.New, sharedKey[:], salt, info)
	
	sessionKey := make([]byte, 32)
	if _, err := io.ReadFull(kdf, sessionKey); err != nil {
		return nil, err
	}
	return sessionKey, nil
}

func newError(values ...interface{}) *errors.Error {
	return errors.New(values...)
}