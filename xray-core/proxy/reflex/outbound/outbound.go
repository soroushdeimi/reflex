package outbound

import (
	"context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

type Handler struct {
	config *reflex.OutboundConfig
}

func (h *Handler) Process(_ context.Context, link *transport.Link, _ internet.Dialer) error {
	if link == nil {
		return nil
	}
	_ = link.Reader
	_ = link.Writer
	return nil
}

func init() {
	common.Must(common.RegisterConfig((*reflex.OutboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*reflex.OutboundConfig))
	}))
}

func New(_ context.Context, config *reflex.OutboundConfig) (proxy.Outbound, error) {
	return &Handler{config: config}, nil
}
