package inbound

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport"
)

type bufferConn struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *bufferConn) Read(_ []byte) (int, error) { return 0, io.EOF }

func (c *bufferConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(p)
}

func (c *bufferConn) Bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]byte, c.buf.Len())
	copy(out, c.buf.Bytes())
	return out
}

func (c *bufferConn) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Len()
}

func (c *bufferConn) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

func (c *bufferConn) Close() error                       { return nil }
func (c *bufferConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *bufferConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *bufferConn) SetDeadline(_ time.Time) error      { return nil }
func (c *bufferConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *bufferConn) SetWriteDeadline(_ time.Time) error { return nil }

type testDispatcher struct{}

func (d *testDispatcher) Type() interface{} { return routing.DispatcherType() }
func (d *testDispatcher) Start() error       { return nil }
func (d *testDispatcher) Close() error       { return nil }

func (d *testDispatcher) Dispatch(ctx context.Context, dest xnet.Destination) (*transport.Link, error) {
	return &transport.Link{
		Reader: buf.NewReader(bytes.NewReader(nil)),
		Writer: buf.Discard,
	}, nil
}

func (d *testDispatcher) DispatchLink(ctx context.Context, dest xnet.Destination, link *transport.Link) error {
	return nil
}

func newCoreContextForTests(t *testing.T) context.Context {
	t.Helper()

	instance, err := core.New(&core.Config{})
	if err != nil {
		t.Fatalf("failed to build core instance: %v", err)
	}

	// core.MustFromContext() uses an internal key with this type/value pair.
	return context.WithValue(context.Background(), core.XrayKey(1), instance)
}

func TestCoverageProcessPaths(t *testing.T) {
	hAny, err := New(context.Background(), &reflex.InboundConfig{})
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}
	h := hAny.(*Handler)

	// POST-like path without fallback should return fallback error.
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	go func() {
		defer clientConn.Close()
		payload := append([]byte("POST /api HTTP/1.1\r\nHost: example.com\r\n\r\n"), bytes.Repeat([]byte("A"), 80)...)
		_, _ = clientConn.Write(payload)
	}()

	if err := h.Process(context.Background(), 0, serverConn, &testDispatcher{}); err == nil {
		t.Fatal("expected process to fail without fallback")
	}
}

func TestCoverageHandleDataHappyPath(t *testing.T) {
	h := createTestHandler()
	ctx := newCoreContextForTests(t)

	sess, err := createTestSession()
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	// Destination header + payload; request path writes payload to upstream and then exits on EOF.
	frameData := []byte{0x01, 127, 0, 0, 1, 0x00, 0x50, 0x68, 0x69}
	reader := bufio.NewReader(bytes.NewReader(nil))
	conn := &bufferConn{}
	user := h.clients[0]

	if err := h.handleData(ctx, frameData, conn, &testDispatcher{}, sess, user, reader); err != nil {
		t.Fatalf("handleData should succeed in controlled test path: %v", err)
	}
}

func TestCoverageHandleFallbackRoundTrip(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		targetConn, err := ln.Accept()
		if err != nil {
			return
		}
		defer targetConn.Close()
		_, _ = io.Copy(io.Discard, targetConn)
		_, _ = targetConn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"))
	}()

	hAny, err := New(context.Background(), &reflex.InboundConfig{
		Fallback: &reflex.Fallback{Dest: uint32(ln.Addr().(*net.TCPAddr).Port)},
	})
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}
	h := hAny.(*Handler)

	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	go func() {
		defer clientConn.Close()
		_, _ = clientConn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	}()

	ctx := newCoreContextForTests(t)
	reader := bufio.NewReader(serverConn)
	_ = h.handleFallback(ctx, reader, serverConn)
	<-done
}

func TestCoverageHandshakeErrorBranches(t *testing.T) {
	h := createTestHandler()

	invalidID := uuid.New()
	clientHS := &ClientHandshake{
		UserID:    [16]byte(invalidID),
		Timestamp: time.Now().Unix(),
	}
	conn := &bufferConn{}
	if err := h.processHandshake(bufio.NewReader(bytes.NewReader(nil)), conn, &testDispatcher{}, context.Background(), clientHS); err == nil {
		t.Fatal("expected authentication failure")
	}
	if !bytes.Contains(conn.Bytes(), []byte("403 Forbidden")) {
		t.Fatal("expected 403 response")
	}

	// readClientHandshakeMagic short-input branch.
	var short bytes.Buffer
	short.Write([]byte{0x52, 0x46, 0x58, 0x4C}) // magic
	short.Write(make([]byte, 32))               // public key only
	if _, err := h.readClientHandshakeMagic(bufio.NewReader(&short)); err == nil {
		t.Fatal("expected short read error")
	}
}

func TestCoverageTrafficProfileFallbackBranches(t *testing.T) {
	p := &TrafficProfile{
		Name:        "fallback-only",
		PacketSizes: []PacketSizeDist{{Size: 333, Weight: 0}},
		Delays:      []DelayDist{{Delay: 9 * time.Millisecond, Weight: 0}},
	}

	if got := p.GetPacketSize(); got != 333 {
		t.Fatalf("expected packet size fallback 333, got %d", got)
	}
	if got := p.GetDelay(); got != 9*time.Millisecond {
		t.Fatalf("expected delay fallback 9ms, got %v", got)
	}
}

func TestCoverageHandleDataErrorBranches(t *testing.T) {
	h := createTestHandler()
	ctx := newCoreContextForTests(t)

	sess, err := createTestSession()
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	user := &protocol.MemoryUser{}
	conn := &bufferConn{}

	// parseDestination failure branch.
	if err := h.handleData(ctx, []byte{0x01}, conn, &testDispatcher{}, sess, user, bufio.NewReader(bytes.NewReader(nil))); err == nil {
		t.Fatal("expected parse destination error")
	}
}

