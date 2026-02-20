package outbound

import (
	"context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

type Handler struct{}

func (inst *Handler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	return nil
}

func buildOutbound(ctx context.Context, config interface{}) (interface{}, error) {
	return &Handler{}, nil
}

func init() {
	common.Must(common.RegisterConfig((*reflex.OutboundConfig)(nil), buildOutbound))
}