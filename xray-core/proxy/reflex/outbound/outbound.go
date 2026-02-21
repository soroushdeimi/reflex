// Package outbound implements the Reflex outbound handler (stub).
package outbound

import (
	"context"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

func init() {
	common.Must(common.RegisterConfig((*reflex.OutboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*reflex.OutboundConfig))
	}))
}

// Handler is the Reflex outbound handler (stub).
type Handler struct {
	config *reflex.OutboundConfig
}

// Process implements proxy.Outbound.Process().
func (h *Handler) Process(ctx context.Context, link *transport.Link, d internet.Dialer) error {
	if h.config == nil {
		return errors.New("reflex outbound config is nil")
	}
	if d == nil {
		return errors.New("reflex outbound dialer is nil")
	}
	if link == nil || link.Reader == nil || link.Writer == nil {
		return errors.New("reflex outbound link is invalid")
	}

	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) > 0 {
		outbounds[len(outbounds)-1].Name = "reflex"
	}

	dest := net.TCPDestination(net.ParseAddress(h.config.GetAddress()), net.Port(h.config.GetPort()))
	conn, err := d.Dial(ctx, dest)
	if err != nil {
		return errors.New("reflex outbound failed to dial destination").Base(err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Time{}); err != nil {
		errors.LogInfoInner(ctx, err, "reflex outbound failed to clear deadline")
	}

	requestDone := func() error {
		return buf.Copy(link.Reader, buf.NewWriter(conn))
	}
	responseDone := func() error {
		return buf.Copy(buf.NewReader(conn), link.Writer)
	}

	if err := task.Run(ctx, requestDone, task.OnSuccess(responseDone, task.Close(link.Writer))); err != nil {
		return errors.New("reflex outbound connection ended").Base(err)
	}
	return nil
}

// New creates a new Reflex outbound handler.
func New(ctx context.Context, config *reflex.OutboundConfig) (proxy.Outbound, error) {
	_ = ctx
	return &Handler{config: config}, nil
}
