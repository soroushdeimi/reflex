package outbound

import (
	"context"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

type Handler struct {
	server net.Destination
	id     string
}

func (h *Handler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	// اینجا بعداً منطق اصلی رو اضافه می‌کنیم
	return nil
}

func init() {
	common.Must(common.RegisterConfig((*reflex.OutboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*reflex.OutboundConfig))
	}))
}

func New(ctx context.Context, config *reflex.OutboundConfig) (proxy.Outbound, error) {
	handler := &Handler{
		server: net.TCPDestination(net.ParseAddress(config.Address), net.Port(config.Port)),
		id:     config.Id,
	}
	return handler, nil
}

