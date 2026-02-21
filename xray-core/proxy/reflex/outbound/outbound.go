package outbound

import (
	"context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/reflex"
)

type Handler struct {
	config *reflex.OutboundConfig
}

func (h *Handler) Process(ctx context.Context, link *proxy.Link, dialer proxy.Dialer) error {
	// فعلاً خالی — بعداً منطق اتصال اضافه می‌کنیم
	return nil
}

func init() {
	common.Must(common.RegisterConfig((*reflex.OutboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*reflex.OutboundConfig))
	}))
}

func New(ctx context.Context, config *reflex.OutboundConfig) (proxy.OutboundHandler, error) {
	return &Handler{
		config: config,
	}, nil
}
