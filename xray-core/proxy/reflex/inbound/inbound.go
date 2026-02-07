package inbound

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common"
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

// --- Constants & Structures ---

const ReflexMagic = 0x5246584C // "REFX"

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

// --- Handler Definition ---

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

// --- Initialization ---

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

// --- Core Process Logic ---

func (h *Handler) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	reader := bufio.NewReader(conn)

	// 1. Peek to check for Magic Number
	peeked, err := reader.Peek(4)
	if err != nil {
		return newError("failed to peek connection").Base(err)
	}

	magic := binary.BigEndian.Uint32(peeked[0:4])
	if magic == ReflexMagic {
		return h.handleReflexMagic(reader, conn, dispatcher, ctx)
	}

	// 2. If not magic, send to fallback (Active Probing Resistance)
	return h.handleFallback(ctx, reader, conn)
}

func (h *Handler) handleFallback(ctx context.Context, reader *bufio.Reader, conn stat.Connection) error {
	return newError("fallback triggered: invalid protocol")
}

func (h *Handler) handleReflexMagic(reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, ctx context.Context) error {
	// 1. Consume the Magic Bytes
	magicBuf := make([]byte, 4)
	if _, err := io.ReadFull(reader, magicBuf); err != nil {
		return newError("failed to read magic").Base(err)
	}

	// 2. Read Client Handshake fields
	var clientHS ClientHandshake

	if _, err := io.ReadFull(reader, clientHS.PublicKey[:]); err != nil {
		return newError("failed to read public key").Base(err)
	}
	if _, err := io.ReadFull(reader, clientHS.UserID[:]); err != nil {
		return newError("failed to read user ID").Base(err)
	}

	// (Skipping PolicyReq reading for simplicity in this step)

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
	// 1. Generate Server Ephemeral Keys
	serverPriv, serverPub := generateKeyPair()
	_ = serverPub // Silence unused variable error

	// 2. Derive Shared Key & Session Key
	sharedKey := deriveSharedKey(serverPriv, clientHS.PublicKey)
	sessionKey := deriveSessionKey(sharedKey, []byte("reflex-session"))
	_ = sessionKey // Silence unused variable error

	// 3. Authenticate User
	_, err := h.authenticateUserBytes(clientHS.UserID)
	if err != nil {
		return h.handleFallback(ctx, reader, conn)
	}

	// 4. Send Response (Fake HTTP 200)
	response := []byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n")
	conn.Write(response)

	return nil
}

// --- Crypto & Helper Functions ---

func generateKeyPair() ([32]byte, [32]byte) {
	var privateKey [32]byte
	var publicKey [32]byte
	rand.Read(privateKey[:])
	curve25519.ScalarBaseMult(&publicKey, &privateKey)
	return privateKey, publicKey
}

func deriveSharedKey(privateKey, peerPublicKey [32]byte) [32]byte {
	var shared [32]byte
	curve25519.ScalarMult(&shared, &privateKey, &peerPublicKey)
	return shared
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

// newError creates a new error in the Xray context
// UPDATED: Removed .Path() as it is not available in this version
func newError(values ...interface{}) *errors.Error {
	return errors.New(values...)
}
