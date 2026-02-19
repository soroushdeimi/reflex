package inbound

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport/internet/stat"
	"google.golang.org/protobuf/proto"
)

// Handler is the inbound handler for Reflex protocol
type Handler struct {
	policyManager policy.Manager
	validator     *Validator
	fallback      *FallbackConfig
	config        *reflex.InboundConfig
}

// FallbackConfig holds fallback configuration
type FallbackConfig struct {
	Dest uint32
	Path string
}

// Validator manages user authentication
type Validator struct {
	sync.RWMutex
	users map[string]*protocol.MemoryUser
}

// NewValidator creates a new validator
func NewValidator() *Validator {
	return &Validator{
		users: make(map[string]*protocol.MemoryUser),
	}
}

// Add adds a user
func (v *Validator) Add(user *protocol.MemoryUser) error {
	v.Lock()
	defer v.Unlock()

	account := user.Account.(*MemoryAccount)
	v.users[account.ID] = user
	return nil
}

// Get retrieves a user by ID
func (v *Validator) Get(userID string) (*protocol.MemoryUser, bool) {
	v.RLock()
	defer v.RUnlock()

	user, found := v.users[userID]
	return user, found
}

// MemoryAccount implements protocol.Account
type MemoryAccount struct {
	ID     string
	Policy string
}

// Equals compares accounts
func (a *MemoryAccount) Equals(account protocol.Account) bool {
	reflexAccount, ok := account.(*MemoryAccount)
	if !ok {
		return false
	}
	return a.ID == reflexAccount.ID
}

// ToProto converts to protobuf message
func (a *MemoryAccount) ToProto() proto.Message {
	return &reflex.Account{Id: a.ID}
}

// New creates a new Reflex inbound handler
func New(ctx context.Context, config *reflex.InboundConfig) (*Handler, error) {
	v := core.MustFromContext(ctx)

	handler := &Handler{
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
		validator:     NewValidator(),
		config:        config,
	}

	// Add users
	for _, user := range config.Clients {
		u := &protocol.MemoryUser{
			Email: user.Id,
			Account: &MemoryAccount{
				ID:     user.Id,
				Policy: user.Policy,
			},
		}
		if err := handler.validator.Add(u); err != nil {
			return nil, err
		}
	}

	// Setup fallback
	if config.Fallback != nil {
		handler.fallback = &FallbackConfig{
			Dest: config.Fallback.Dest,
			Path: config.Fallback.Path,
		}
	}

	return handler, nil
}

// Network returns supported networks
func (h *Handler) Network() []net.Network {
	return []net.Network{net.Network_TCP}
}

// Process handles incoming connection
func (h *Handler) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	// Set handshake deadline
	sessionPolicy := h.policyManager.ForLevel(0)
	if err := conn.SetReadDeadline(time.Now().Add(sessionPolicy.Timeouts.Handshake)); err != nil {
		return newError("failed to set read deadline").Base(err)
	}

	// Wrap in buffered reader for peeking
	reader := bufio.NewReader(conn)

	// Peek first 4 bytes for magic number
	peeked, err := reader.Peek(4)
	if err != nil {
		return newError("failed to peek magic").Base(err)
	}

	// Check magic number
	magic := binary.BigEndian.Uint32(peeked)
	if magic == reflex.ReflexMagic {
		return h.handleReflexHandshake(ctx, reader, conn, dispatcher)
	}

	// Not Reflex protocol - fallback
	return h.handleFallback(ctx, reader, conn)
}

// handleReflexHandshake processes Reflex handshake
func (h *Handler) handleReflexHandshake(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher) error {
	// Read magic (already peeked, but consume it)
	var magic uint32
	if err := binary.Read(reader, binary.BigEndian, &magic); err != nil {
		return newError("failed to read magic").Base(err)
	}

	// Read handshake data length (2 bytes)
	var dataLen uint16
	if err := binary.Read(reader, binary.BigEndian, &dataLen); err != nil {
		return newError("failed to read data length").Base(err)
	}

	if dataLen > 4096 { // Sanity check
		return newError("handshake data too large: ", dataLen)
	}

	// Read handshake data
	hsData := make([]byte, dataLen)
	if _, err := io.ReadFull(reader, hsData); err != nil {
		return newError("failed to read handshake data").Base(err)
	}

	// Parse client handshake
	clientHS, err := reflex.UnmarshalClientHandshake(hsData)
	if err != nil {
		return newError("failed to unmarshal handshake").Base(err)
	}

	// Validate timestamp
	if !reflex.ValidateTimestamp(clientHS.Timestamp) {
		return newError("invalid timestamp")
	}

	// Authenticate user
	userID := reflex.ParseUUID(clientHS.UserID)
	user, found := h.validator.Get(userID)
	if !found {
		return h.handleFallback(ctx, reader, conn)
	}

	// Generate server key pair
	serverPriv, serverPub, err := reflex.GenerateKeyPair()
	if err != nil {
		return newError("failed to generate key pair").Base(err)
	}

	// Derive shared key
	sharedKey, err := reflex.DeriveSharedKey(serverPriv, clientHS.PublicKey)
	if err != nil {
		return newError("failed to derive shared key").Base(err)
	}

	// Generate server nonce
	serverNonce, err := reflex.GenerateNonce()
	if err != nil {
		return newError("failed to generate nonce").Base(err)
	}

	// Derive session keys
	sessionKeys, err := reflex.DeriveSessionKeys(sharedKey, clientHS.Nonce, serverNonce)
	if err != nil {
		return newError("failed to derive session keys").Base(err)
	}

	// Create server handshake response
	serverHS := &reflex.ServerHandshake{
		PublicKey:   serverPub,
		Timestamp:   time.Now().Unix(),
		PolicyGrant: []byte{}, // TODO: Implement policy grant
	}

	// Marshal server handshake
	serverHSData := reflex.MarshalServerHandshake(serverHS)

	// Send response: magic + length + data
	response := make([]byte, 4+2+len(serverHSData))
	binary.BigEndian.PutUint32(response[0:4], reflex.ReflexMagic)
	binary.BigEndian.PutUint16(response[4:6], uint16(len(serverHSData)))
	copy(response[6:], serverHSData)

	if _, err := conn.Write(response); err != nil {
		return newError("failed to send handshake response").Base(err)
	}

	// Clear handshake deadline
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return newError("failed to clear deadline").Base(err)
	}

	// Setup session context
	inbound := session.InboundFromContext(ctx)
	if inbound == nil {
		inbound = &session.Inbound{}
		ctx = session.ContextWithInbound(ctx, inbound)
	}
	inbound.Name = "reflex"
	inbound.User = user

	// Handle session (TODO: Step 3)
	return h.handleSession(ctx, reader, conn, dispatcher, sessionKeys)
}

// handleSession handles established session
func (h *Handler) handleSession(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, keys *reflex.SessionKeys) error {
	// TODO: Step 3 - Implement data encryption/decryption
	return newError("session handling not implemented yet")
}

// handleFallback forwards connection to fallback destination
func (h *Handler) handleFallback(ctx context.Context, reader *bufio.Reader, conn stat.Connection) error {
	if h.fallback == nil {
		return newError("fallback not configured")
	}

	// TODO: Step 4 - Implement fallback logic
	return newError("fallback not implemented yet")
}

// newError creates error with context
func newError(values ...interface{}) *errors.Error {
	return errors.New(values...).AtWarning()
}

func init() {
	common.Must(common.RegisterConfig((*reflex.InboundConfig)(nil),
		func(ctx context.Context, config interface{}) (interface{}, error) {
			return New(ctx, config.(*reflex.InboundConfig))
		}))
}
