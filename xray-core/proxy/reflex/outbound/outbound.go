package outbound

import (
	"context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

// Handler is an outbound handler for reflex protocol
type Handler struct {
	server *protocol.ServerSpec
}

// New creates a new reflex outbound handler
func New(ctx context.Context, config *reflex.OutboundConfig) (proxy.Outbound, error) {
	if config.Address == "" {
		return nil, errors.New("address is not set")
	}
	if config.Port == 0 {
		return nil, errors.New("port is not set")
	}
	if config.Id == "" {
		return nil, errors.New("id is not set")
	}

	dest := net.TCPDestination(net.ParseAddress(config.Address), net.Port(config.Port))
	user := &protocol.MemoryUser{
		Email: config.Id,
	}

	server := &protocol.ServerSpec{
		Destination: dest,
		User:        user,
	}

	handler := &Handler{
		server: server,
	}

	return handler, nil
}

// Process implements proxy.Outbound.Process()
func (h *Handler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	// اینجا بعداً منطق اصلی رو اضافه می‌کنیم
	return nil
}

func init() {
	common.Must(common.RegisterConfig((*reflex.OutboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*reflex.OutboundConfig))
	}))
}
