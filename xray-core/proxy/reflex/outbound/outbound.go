package outbound

import (
	"context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

// Handler is the outbound connection handler for Reflex protocol
type Handler struct {
	policyManager policy.Manager
	config        *reflex.OutboundConfig
}

// New creates a new Reflex outbound handler
func New(ctx context.Context, config *reflex.OutboundConfig) (*Handler, error) {
	v := core.MustFromContext(ctx)

	handler := &Handler{
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
		config:        config,
	}

	return handler, nil
}

// Process dials and handles outbound connection
func (h *Handler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	// TODO: Step 2 - Implement client handshake
	// TODO: Step 3 - Implement encryption
	// For now, just return not implemented error

	return newError("reflex outbound not fully implemented yet")
}

// newError creates a new error
func newError(values ...interface{}) *errors.Error {
	return errors.New(values...)
}

func init() {
	common.Must(common.RegisterConfig((*reflex.OutboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*reflex.OutboundConfig))
	}))
}
