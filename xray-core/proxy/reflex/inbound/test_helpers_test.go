package inbound

import (
	"context"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport"
)

// panicDispatcher is a test helper that must never be called.
// If it's called, the test should fail immediately.
type panicDispatcher struct{}

func (d *panicDispatcher) Type() interface{} { return (*panicDispatcher)(nil) }
func (d *panicDispatcher) Start() error      { return nil }
func (d *panicDispatcher) Close() error      { return nil }

func (d *panicDispatcher) Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error) {
	panic("dispatcher must not be called in this test")
}

func (d *panicDispatcher) DispatchLink(ctx context.Context, dest net.Destination, link *transport.Link) error {
	panic("dispatcher must not be called in this test")
}
