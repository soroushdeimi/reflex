package outbound

import (
	"context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*Config))
	}))
}

// Handler is the outbound connection handler for Reflex protocol
type Handler struct {
	config        *Config
	policyManager policy.Manager
	ctx           context.Context
}

// New creates a new Reflex outbound handler
func New(ctx context.Context, config *Config) (*Handler, error) {
	v := core.MustFromContext(ctx)

	handler := &Handler{
		config:        config,
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
		ctx:           ctx,
	}

	return handler, nil
}

// Process handles outbound connections
func (h *Handler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	// TODO: Step 2 - Implement handshake
	// TODO: Step 3 - Implement encryption and session handling

	return errors.New("outbound not yet implemented")
}

func (h *Handler) Network() []xnet.Network {
	return []xnet.Network{xnet.Network_TCP}
}
