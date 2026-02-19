package inbound

import (
	"context"
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

// Handler is the inbound connection handler for Reflex protocol
type Handler struct {
	policyManager policy.Manager
	validator     *Validator
	fallback      *FallbackConfig
	config        *reflex.InboundConfig
}

// FallbackConfig holds fallback destination
type FallbackConfig struct {
	Dest uint32
	Path string
}

// Validator manages user validation
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

// Add adds a user to validator
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

// Equals compares two accounts
func (a *MemoryAccount) Equals(account protocol.Account) bool {
	reflexAccount, ok := account.(*MemoryAccount)
	if !ok {
		return false
	}
	return a.ID == reflexAccount.ID
}

// AsAccount converts to proto Account
func (a *MemoryAccount) AsAccount() (protocol.Account, error) {
	return a, nil
}

// ToProto implements protocol.Account.ToProto()
func (a *MemoryAccount) ToProto() proto.Message {
	return &reflex.Account{
		Id: a.ID,
	}
}

// New creates a new Reflex inbound handler
func New(ctx context.Context, config *reflex.InboundConfig) (*Handler, error) {
	v := core.MustFromContext(ctx)

	handler := &Handler{
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
		validator:     NewValidator(),
		config:        config,
	}

	// Add users to validator
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

	// Setup fallback if configured
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
	// Get session policy
	sessionPolicy := h.policyManager.ForLevel(0)

	// Set read deadline with timeout
	if err := conn.SetReadDeadline(time.Now().Add(sessionPolicy.Timeouts.Handshake)); err != nil {
		return newError("failed to set read deadline").Base(err)
	}

	// Create inbound context
	inbound := session.InboundFromContext(ctx)
	if inbound == nil {
		inbound = &session.Inbound{}
		ctx = session.ContextWithInbound(ctx, inbound)
	}
	inbound.Name = "reflex"

	// TODO: Step 2 - Implement handshake here
	// TODO: Step 3 - Implement encryption/decryption
	// TODO: Step 4 - Implement fallback logic

	return newError("reflex protocol not fully implemented yet")
}

// newError creates a new error with Reflex prefix
func newError(values ...interface{}) *errors.Error {
	return errors.New(values...).AtWarning()
}

func init() {
	common.Must(common.RegisterConfig((*reflex.InboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*reflex.InboundConfig))
	}))
}
