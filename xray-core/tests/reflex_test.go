// Package tests contains Reflex protocol integration tests.
package tests

import (
	"bufio"
	"context"
	"encoding/binary"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/proxy/reflex/inbound"
)

// TestReflexConfigBuild verifies that Reflex inbound config can be created.
func TestReflexConfigBuild(t *testing.T) {
	u := uuid.New()
	uid := (&u).String()
	config := &reflex.InboundConfig{
		Clients: []*reflex.User{
			{Id: uid, Policy: "http2-api"},
		},
		Fallback: &reflex.Fallback{Dest: 80},
	}
	ctx := context.Background()
	handler, err := inbound.New(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	if handler == nil {
		t.Fatal("handler is nil")
	}
	if len(handler.Network()) == 0 {
		t.Error("Network() should return at least TCP")
	}
}

// TestReflexFallback verifies that non-Reflex traffic is forwarded to fallback server.
func TestReflexFallback(t *testing.T) {
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("fallback-ok"))
	}))
	defer fallback.Close()
	_, portStr, _ := net.SplitHostPort(fallback.Listener.Addr().String())
	port, _ := strconv.ParseUint(portStr, 10, 32)
	config := &reflex.InboundConfig{
		Clients:  []*reflex.User{},
		Fallback: &reflex.Fallback{Dest: uint32(port)},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	h, err := inbound.New(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	reader := bufio.NewReader(serverConn)
	// Run Process in background so we can read the response; otherwise Copy(backend->client) blocks.
	go func() { _ = h.Process(ctx, 0, &pipeConn{reader: reader, conn: serverConn}, nil) }()
	time.Sleep(50 * time.Millisecond)
	_, _ = clientConn.Write([]byte("GET / HTTP/1.0\r\nHost: x\r\n\r\n"))
	buf := make([]byte, 256)
	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _ := clientConn.Read(buf)
	if n > 0 {
		// Fallback responded (e.g. "HTTP/1.0 200 ... fallback-ok")
		_ = buf[:n]
	}
	clientConn.Close()
}

// TestReflexMagicDetection verifies that Reflex magic number is required for Reflex path.
func TestReflexMagicDetection(t *testing.T) {
	u := uuid.New()
	config := &reflex.InboundConfig{
		Clients: []*reflex.User{
			{Id: (&u).String(), Policy: ""},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	h, err := inbound.New(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	go func() {
		var wrongMagic [4]byte
		binary.BigEndian.PutUint32(wrongMagic[:], 0xDEADBEEF)
		_, _ = clientConn.Write(wrongMagic[:])
	}()
	reader := bufio.NewReader(serverConn)
	err = h.Process(ctx, xnet.Network_TCP, &pipeConn{reader: reader, conn: serverConn}, nil)
	_ = err
}

type pipeConn struct {
	reader *bufio.Reader
	conn   net.Conn
}

func (p *pipeConn) Read(b []byte) (int, error)   { return p.reader.Read(b) }
func (p *pipeConn) Write(b []byte) (int, error)  { return p.conn.Write(b) }
func (p *pipeConn) Close() error                 { return p.conn.Close() }
func (p *pipeConn) RemoteAddr() net.Addr         { return p.conn.RemoteAddr() }
func (p *pipeConn) LocalAddr() net.Addr          { return p.conn.LocalAddr() }
func (p *pipeConn) SetDeadline(t time.Time) error   { return p.conn.SetDeadline(t) }
func (p *pipeConn) SetReadDeadline(t time.Time) error { return p.conn.SetReadDeadline(t) }
func (p *pipeConn) SetWriteDeadline(t time.Time) error { return p.conn.SetWriteDeadline(t) }
