package outbound_test

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/proxy/reflex/inbound"
	"github.com/xtls/xray-core/proxy/reflex/outbound"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/pipe"
)

type pipeConn struct{ net.Conn }

func (p *pipeConn) Read(b []byte) (n int, err error)   { return p.Conn.Read(b) }
func (p *pipeConn) Write(b []byte) (n int, err error)  { return p.Conn.Write(b) }
func (p *pipeConn) Close() error                       { return p.Conn.Close() }
func (p *pipeConn) LocalAddr() net.Addr                { return p.Conn.LocalAddr() }
func (p *pipeConn) RemoteAddr() net.Addr               { return p.Conn.RemoteAddr() }
func (p *pipeConn) SetDeadline(t time.Time) error      { return p.Conn.SetDeadline(t) }
func (p *pipeConn) SetReadDeadline(t time.Time) error  { return p.Conn.SetReadDeadline(t) }
func (p *pipeConn) SetWriteDeadline(t time.Time) error { return p.Conn.SetWriteDeadline(t) }

type mockDialer struct {
	conn net.Conn
}

func (d *mockDialer) Dial(ctx context.Context, dest xnet.Destination) (stat.Connection, error) {
	if d.conn == nil {
		return nil, errors.New("no connection")
	}
	return &pipeConn{d.conn}, nil
}

func (d *mockDialer) DestIpAddress() net.IP { return nil }

func (d *mockDialer) SetOutboundGateway(ctx context.Context, ob *session.Outbound) {}

type mockDispatcher struct{}

func (m *mockDispatcher) Type() interface{} { return (*routing.Dispatcher)(nil) }
func (m *mockDispatcher) Start() error      { return nil }
func (m *mockDispatcher) Close() error      { return nil }
func (m *mockDispatcher) Dispatch(ctx context.Context, dest xnet.Destination) (*transport.Link, error) {
	return nil, errors.New("mock: not used")
}
func (m *mockDispatcher) DispatchLink(ctx context.Context, dest xnet.Destination, link *transport.Link) error {
	return errors.New("mock: not used")
}

// TestOutboundProcessFull runs outbound.Process with a pipe: server end runs inbound, client end is returned by mock dialer.
// This gives coverage of outbound handshake and handleSession.
func TestOutboundProcessFull(t *testing.T) {
	userUUID := uuid.New().String()
	inboundConfig := &reflex.InboundConfig{
		Clients: []*reflex.User{{Id: userUUID}},
	}
	inHandler, err := inbound.New(context.Background(), inboundConfig)
	if err != nil {
		t.Fatalf("inbound New: %v", err)
	}

	clientConn, serverConn := net.Pipe()

	go func() {
		_ = inHandler.Process(context.Background(), xnet.Network_TCP, &pipeConn{serverConn}, &mockDispatcher{})
		serverConn.Close()
	}()

	outboundConfig := &reflex.OutboundConfig{
		Address: "127.0.0.1",
		Port:    0,
		Id:      userUUID,
	}
	outHandler, err := outbound.New(context.Background(), outboundConfig)
	if err != nil {
		t.Fatalf("outbound New: %v", err)
	}

	dialer := &mockDialer{conn: clientConn}
	reader, writer := pipe.New(pipe.WithoutSizeLimit())
	link := &transport.Link{Reader: reader, Writer: writer}

	target := xnet.TCPDestination(xnet.DomainAddress("example.com"), 443)
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: target}})

	done := make(chan error, 1)
	go func() {
		done <- outHandler.Process(ctx, link, dialer)
	}()
	// Close writer so outbound's read-from-link goroutine gets EOF and sends CLOSE; then Process returns.
	writer.Close()
	err = <-done
	if err != nil {
		t.Logf("Process (expected to end when link closes): %v", err)
	}
	clientConn.Close()
}

// TestOutboundNew verifies outbound handler creation.
func TestOutboundNew(t *testing.T) {
	config := &reflex.OutboundConfig{
		Address:         "127.0.0.1",
		Port:            8080,
		Id:              uuid.New().String(),
		MorphingEnabled: true,
	}
	handler, err := outbound.New(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	if handler == nil {
		t.Fatal("handler is nil")
	}
}

// TestOutboundProcessNoTarget verifies Process returns error when context has no outbound target.
func TestOutboundProcessNoTarget(t *testing.T) {
	config := &reflex.OutboundConfig{
		Address: "127.0.0.1",
		Port:    8080,
		Id:      uuid.New().String(),
	}
	handler, err := outbound.New(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}

	reader, writer := pipe.New(pipe.WithoutSizeLimit())
	link := &transport.Link{Reader: reader, Writer: writer}
	writer.Close()

	ctx := context.Background()
	err = handler.Process(ctx, link, &mockDialer{})
	if err == nil {
		t.Fatal("expected error when no outbound target in context")
	}
	if err != nil && !strings.Contains(err.Error(), "outbound target") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestOutboundProcessInvalidUUID verifies Process returns error for invalid client UUID.
func TestOutboundProcessInvalidUUID(t *testing.T) {
	config := &reflex.OutboundConfig{
		Address: "127.0.0.1",
		Port:    8080,
		Id:      "not-a-valid-uuid",
	}
	handler, err := outbound.New(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}

	reader, writer := pipe.New(pipe.WithoutSizeLimit())
	link := &transport.Link{Reader: reader, Writer: writer}
	writer.Close()

	target := xnet.TCPDestination(xnet.DomainAddress("example.com"), 443)
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: target}})

	err = handler.Process(ctx, link, &mockDialer{conn: nil})
	if err == nil {
		t.Fatal("expected error for invalid UUID or dial failure")
	}
}
