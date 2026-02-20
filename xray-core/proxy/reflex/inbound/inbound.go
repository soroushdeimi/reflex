package inbound

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"strings"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/core"
	feature_inbound "github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport/internet/stat"
)

const reflexPeekSize = 72

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*Config))
	}))
}

// Handler is the inbound connection handler for Reflex protocol
type Handler struct {
	clients           reflex.Validator
	policyManager     policy.Manager
	inboundManager    feature_inbound.Manager
	defaultDispatcher routing.Dispatcher
	ctx               context.Context
	fallback          *FallbackConfig
}

// New creates a new Reflex inbound handler
func New(ctx context.Context, config *Config) (*Handler, error) {
	v := core.MustFromContext(ctx)

	handler := &Handler{
		clients:           reflex.NewMemoryValidator(),
		policyManager:     v.GetFeature(policy.ManagerType()).(policy.Manager),
		inboundManager:    v.GetFeature(feature_inbound.ManagerType()).(feature_inbound.Manager),
		defaultDispatcher: v.GetFeature(routing.DispatcherType()).(routing.Dispatcher),
		ctx:               ctx,
		fallback:          config.Fallback,
	}

	// Add clients to the validator
	for _, client := range config.Clients {
		account, err := (&reflex.Account{
			ID:     client.ID,
			Policy: client.Policy,
		}).AsAccount()
		if err != nil {
			return nil, errors.New("failed to create account").Base(err)
		}
		user := &protocol.MemoryUser{
			Email:   client.ID,
			Account: account,
		}
		if err := handler.clients.Add(user); err != nil {
			return nil, errors.New("failed to add user").Base(err)
		}
	}

	return handler, nil
}

// Network returns the network type(s) supported by this handler
func (h *Handler) Network() []xnet.Network {
	return []xnet.Network{xnet.Network_TCP}
}

// Process processes an inbound connection (Step 1: Basic structure only)
func (h *Handler) Process(ctx context.Context, network xnet.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	reader := bufio.NewReader(conn)

	peeked, err := reader.Peek(reflexPeekSize)
	if err != nil && err != io.EOF && err != bufio.ErrBufferFull {
		return err
	}
	if !h.isReflexHandshake(peeked) {
		return h.handleFallback(ctx, reader, conn)
	}

	// TODO: Step 2 - Implement handshake
	// TODO: Step 3 - Implement encryption and session handling

	return nil
}

func (h *Handler) isReflexHandshake(peeked []byte) bool {
	return isReflexMagic(peeked) || isHTTPPostLike(peeked)
}

func isReflexMagic(peeked []byte) bool {
	if len(peeked) < 4 {
		return false
	}
	return binary.BigEndian.Uint32(peeked[:4]) == reflex.ReflexMagic
}

func isHTTPPostLike(peeked []byte) bool {
	return len(peeked) >= 4 && strings.EqualFold(string(peeked[:4]), "POST")
}

// handleFallback handles non-Reflex connections (stub for Step 1)
func (h *Handler) handleFallback(ctx context.Context, reader *bufio.Reader, conn stat.Connection) error {
	// Step 1: Basic fallback stub
	return nil
}
