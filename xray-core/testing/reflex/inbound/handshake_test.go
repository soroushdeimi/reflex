package inbound_test

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	coreNet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/proxy/reflex/inbound"
)

// ---------------- fake addr ----------------

type fakeAddr struct{}

func (fakeAddr) Network() string { return "tcp" }
func (fakeAddr) String() string  { return "127.0.0.1:0" }

// ---------------- fake connection ----------------
// ✅ implements net.Conn → stat.Connection

type fakeConn struct {
	readErr error
}

func (f *fakeConn) Read(b []byte) (int, error) {
	if f.readErr != nil {
		return 0, f.readErr
	}
	return 0, io.EOF
}

func (f *fakeConn) Write(b []byte) (int, error) {
	return len(b), nil
}

func (f *fakeConn) Close() error { return nil }

func (f *fakeConn) LocalAddr() net.Addr  { return fakeAddr{} }
func (f *fakeConn) RemoteAddr() net.Addr { return fakeAddr{} }

func (f *fakeConn) SetDeadline(t time.Time) error      { return nil }
func (f *fakeConn) SetReadDeadline(t time.Time) error  { return nil }
func (f *fakeConn) SetWriteDeadline(t time.Time) error { return nil }

// ---------------- helper ----------------

func mustNewHandler(t *testing.T) proxy.Inbound {
	t.Helper()

	h, err := inbound.New(context.Background(), &reflex.InboundConfig{})
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}
	return h
}

// ---------------- tests ----------------

// create handler
func TestNewHandler(t *testing.T) {
	_, err := inbound.New(context.Background(), &reflex.InboundConfig{})
	if err != nil {
		t.Fatal("handler creation failed")
	}
}

// nil connection
func TestProcess_NilConn(t *testing.T) {
	h := mustNewHandler(t)

	err := h.Process(
		context.Background(),
		coreNet.Network_TCP,
		nil,
		nil,
	)

	if err == nil {
		t.Fatal("expected error for nil connection")
	}
}

// unsupported network
func TestProcess_UnsupportedNetwork(t *testing.T) {
	h := mustNewHandler(t)

	err := h.Process(
		context.Background(),
		coreNet.Network_UDP,
		&fakeConn{},
		nil,
	)

	if err == nil {
		t.Fatal("expected error for unsupported network")
	}
}

// EOF during handshake
func TestProcess_EOF(t *testing.T) {
	h := mustNewHandler(t)

	err := h.Process(
		context.Background(),
		coreNet.Network_TCP,
		&fakeConn{readErr: io.EOF},
		nil,
	)

	if err == nil {
		t.Fatal("expected EOF error")
	}
}

// context canceled
func TestProcess_ContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	h := mustNewHandler(t)

	err := h.Process(
		ctx,
		coreNet.Network_TCP,
		&fakeConn{},
		nil,
	)

	if err == nil {
		t.Fatal("expected context canceled error")
	}
}

// read error
func TestProcess_ReadError(t *testing.T) {
	h := mustNewHandler(t)

	err := h.Process(
		context.Background(),
		coreNet.Network_TCP,
		&fakeConn{readErr: errors.New("boom")},
		nil,
	)

	if err == nil {
		t.Fatal("expected read error")
	}
}
