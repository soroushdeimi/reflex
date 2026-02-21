package inbound

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport/internet/stat"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

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

func (a *MemoryAccount) ToProto() protocol.Message {
	return &reflex.Account{
		Id: a.Id,
	}
}

type FallbackConfig struct {
	Dest uint32
}

// --------- Handshake Structs ---------

type ClientHandshake struct {
	PublicKey [32]byte
	UserID    [16]byte
	PolicyReq []byte
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

const ReflexMagic = 0x5246584C // "REFX"

// --------- Handler Methods ---------

func (h *Handler) Network() []net.Network {
	return []net.Network{net.Network_TCP}
}

func (h *Handler) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	reader := bufio.NewReader(conn)

	peeked, err := reader.Peek(64)
	if err != nil {
		return err
	}

	// Magic number check
	if len(peeked) >= 4 {
		magic := binary.BigEndian.Uint32(peeked[0:4])
		if magic == ReflexMagic {
			return h.handleReflexMagic(ctx, reader, conn, dispatcher)
		}
	}

	// HTTP POST-like check
	if h.isHTTPPostLike(peeked) {
		return h.handleReflexHTTP(ctx, reader, conn, dispatcher)
	}

	// fallback
	return h.handleFallback(ctx, reader, conn)
}

// --------- Handshake Methods ---------

func (h *Handler) handleReflexMagic(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher) error {
	fmt.Println("Reflex handshake detected (magic)")

	if _, err := io.ReadFull(reader, make([]byte, 4)); err != nil {
		return err
	}

	var packet ClientHandshakePacket
	if err := binary.Read(reader, binary.BigEndian, &packet.Handshake); err != nil {
		return err
	}

	return h.processHandshake(ctx, reader, conn, dispatcher, packet.Handshake)
}

func (h *Handler) handleReflexHTTP(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher) error {
	fmt.Println("Reflex handshake detected (HTTP POST-like)")

	// ساده‌ترین حالت: parse اولیه HTTP POST-like
	buf, _ := reader.Peek(4096)
	postData := string(buf)
	start := "data\":\""
	idx := 0
	if i := len(start); i < len(postData) {
		idx = i
	}
	// placeholder decode base64
	decoded := make([]byte, 0)
	_ = base64.StdEncoding.Decode(decoded, []byte("...")) // جایگزین با real parse بعداً

	var clientHS ClientHandshake
	// TODO: پر کردن clientHS با داده decode شده
	_ = clientHS

	return h.processHandshake(ctx, reader, conn, dispatcher, clientHS)
}

func (h *Handler) processHandshake(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, clientHS ClientHandshake) error {
	// generate server key pair
	serverPrivate, serverPublic := generateKeyPair()
	sharedKey := deriveSharedKey(serverPrivate, clientHS.PublicKey)
	sessionKey := deriveSessionKey(sharedKey, []byte("reflex-session"))

	// authenticate user
	user, err := h.authenticateUser(clientHS.UserID)
	if err != nil {
		return h.handleFallback(ctx, reader, conn)
	}
	fmt.Println("Authenticated user:", user.Email)

	// prepare ServerHandshake (placeholder policy grant)
	serverHS := ServerHandshake{
		PublicKey:   serverPublic,
		PolicyGrant: []byte{}, // TODO: encrypt policy with sessionKey
	}

	// send HTTP 200 placeholder
	response := []byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"ok\"}")
	conn.Write(response)

	// placeholder for session handling
	return h.handleSession(ctx, reader, conn, dispatcher, sessionKey, user)
}

// --------- Fallback ---------

func (h *Handler) handleFallback(ctx context.Context, reader *bufio.Reader, conn stat.Connection) error {
	fmt.Println("Fallback called")
	return nil
}

// --------- Authentication ---------

func (h *Handler) authenticateUser(userID [16]byte) (*protocol.MemoryUser, error) {
	userIDStr := uuid.UUID(userID).String()
	for _, user := range h.clients {
		if user.Account.(*MemoryAccount).Id == userIDStr {
			return user, nil
		}
	}
	return nil, errors.New("user not found")
}

// --------- Helpers ---------

func (h *Handler) isHTTPPostLike(peeked []byte) bool {
	return len(peeked) >= 4 && string(peeked[:4]) == "POST"
}

func generateKeyPair() (privateKey, publicKey [32]byte) {
	rand.Read(privateKey[:])
	curve25519.ScalarBaseMult(&publicKey, &privateKey)
	return
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

// placeholder
func (h *Handler) handleSession(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, sessionKey []byte, user *protocol.MemoryUser) error {
	fmt.Println("Session started for user:", user.Email)
	return nil
}

// --------- Constructor ---------

func init() {
	common.Must(common.RegisterConfig((*reflex.InboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*reflex.InboundConfig))
	}))
}

func New(ctx context.Context, config *reflex.InboundConfig) (proxy.InboundHandler, error) {
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

/*package inbound

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport/internet/stat"
	"google.golang.org/protobuf/proto"
)

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

// --------- Handshake Struct ---------

type ClientHandshake struct {
	UserID    [16]byte
	Timestamp int64
}

const ReflexMagic = 0x5246584C // "REFX"

// --------- Handler Methods ---------

func (h *Handler) Network() []net.Network {
	return []net.Network{net.Network_TCP}
}

func (h *Handler) Process(
	ctx context.Context,
	network net.Network,
	conn stat.Connection,
	dispatcher routing.Dispatcher,
) error {

	reader := bufio.NewReader(conn)

	peeked, err := reader.Peek(4)
	if err != nil {
		return err
	}

	magic := binary.BigEndian.Uint32(peeked)
	if magic != ReflexMagic {
		return h.handleFallback(ctx, reader, conn)
	}

	return h.handleReflexMagic(ctx, reader, conn)
}

// --------- Real Handshake ---------

func (h *Handler) handleReflexMagic(
	ctx context.Context,
	reader *bufio.Reader,
	conn stat.Connection,
) error {

	fmt.Println("Reflex handshake detected")

	// consume magic
	if _, err := io.ReadFull(reader, make([]byte, 4)); err != nil {
		return err
	}

	var handshake ClientHandshake

	if err := binary.Read(reader, binary.BigEndian, &handshake); err != nil {
		return err
	}

	// timestamp check (anti-replay)
	if time.Since(time.Unix(handshake.Timestamp, 0)) > 30*time.Second {
		return errors.New("handshake expired")
	}

	// authenticate user
	user, err := h.authenticateUser(handshake.UserID)
	if err != nil {
		return errors.New("invalid user")
	}

	fmt.Println("Authenticated user:", user.Email)

	// handshake success (for now just return nil)
	return nil
}

func (h *Handler) handleFallback(
	ctx context.Context,
	reader *bufio.Reader,
	conn stat.Connection,
) error {

	fmt.Println("Fallback called")
	return nil
}

// --------- Authentication ---------

func (h *Handler) authenticateUser(userID [16]byte) (*protocol.MemoryUser, error) {
	userIDStr := uuid.UUID(userID).String()

	for _, user := range h.clients {
		if user.Account.(*MemoryAccount).Id == userIDStr {
			return user, nil
		}
	}

	return nil, errors.New("user not found")
}

// --------- Constructor ---------

func init() {
	common.Must(common.RegisterConfig((*reflex.InboundConfig)(nil),
		func(ctx context.Context, config interface{}) (interface{}, error) {
			return New(ctx, config.(*reflex.InboundConfig))
		}))
}

func New(ctx context.Context, config *reflex.InboundConfig) (proxy.InboundHandler, error) {

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
*/

/*package inbound

import (
	"context"

	"google.golang.org/protobuf/proto"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport/internet/stat"
)

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

func (h *Handler) Network() []net.Network {
	return []net.Network{net.Network_TCP}
}

func (h *Handler) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	println("Reflex inbound Process called")
	return nil
}

func init() {
	common.Must(common.RegisterConfig((*reflex.InboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*reflex.InboundConfig))
	}))
}

func New(ctx context.Context, config *reflex.InboundConfig) (proxy.InboundHandler, error) {
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
}*/
