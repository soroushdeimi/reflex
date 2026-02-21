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

// Handler مدیریت اتصالات خروجی
type Handler struct {
	serverAddress net.Destination
	clientId      string
}

// Process برقراری اتصال به سرور
func (h *Handler) Process(
	ctx context.Context,
	link *transport.Link,
	dialer internet.Dialer,
) error {
	// TODO: Step 2 - handshake
	// TODO: Step 3 - encryption
	return nil
}

// New ساخت Handler جدید
func New(ctx context.Context, config *reflex.OutboundConfig) (proxy.Outbound, error) {
	serverAddress := net.Destination{
		Network: net.Network_TCP,
		Address: net.ParseAddress(config.Address),
		Port:    net.Port(config.Port),
	}

	handler := &Handler{
		serverAddress: serverAddress,
		clientId:      config.Id,
	}

	return handler, nil
}

// init ثبت در Xray
func init() {
	common.Must(common.RegisterConfig(
		(*reflex.OutboundConfig)(nil),
		func(ctx context.Context, config interface{}) (interface{}, error) {
			return New(ctx, config.(*reflex.OutboundConfig))
		},
	))
}
