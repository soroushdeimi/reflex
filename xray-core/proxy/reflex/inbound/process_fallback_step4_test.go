package inbound

import (
	"bytes"
	"context"
	"io"
	stdnet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/reflex"
)

func TestProcessGenericHTTPPostGoesToFallback(t *testing.T) {
	// Start local fallback server.
	ln, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	port := ln.Addr().(*stdnet.TCPAddr).Port

	cfg := &reflex.InboundConfig{
		Fallback: &reflex.Fallback{Dest: uint32(port)},
	}
	h, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// A generic HTTP POST (NOT Reflex endpoint). Must be > 64 bytes for Peek(64).
	req := []byte(
		"POST /login HTTP/1.1\r\n" +
			"Host: example.com\r\n" +
			"User-Agent: curl/8.0\r\n" +
			"Accept: */*\r\n" +
			"Content-Type: application/x-www-form-urlencoded\r\n" +
			"Content-Length: 5\r\n" +
			"\r\n" +
			"hello",
	)
	if len(req) <= 64 {
		t.Fatalf("request too short (%d), need > 64", len(req))
	}

	recvCh := make(chan []byte, 1)
	srvErrCh := make(chan error, 1)

	// Accept one conn and read exactly len(req) bytes.
	go func() {
		c, e := ln.Accept()
		if e != nil {
			srvErrCh <- e
			return
		}
		defer c.Close()

		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))

		buf := make([]byte, len(req))
		_, e = io.ReadFull(c, buf)
		if e != nil {
			srvErrCh <- e
			return
		}
		recvCh <- buf
	}()

	// Simulate inbound TCP conn.
	clientConn, inboundConn := stdnet.Pipe()
	defer clientConn.Close()
	// inboundConn is closed by Process/handleFallback.

	// Run Process (should fallback).
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	procErrCh := make(chan error, 1)
	go func() {
		procErrCh <- h.Process(ctx, net.Network_TCP, inboundConn, routing.Dispatcher(&panicDispatcher{}))
	}()

	// Client sends request then closes.
	go func() {
		_, _ = clientConn.Write(req)
		_ = clientConn.Close()
	}()

	// Verify fallback server received identical bytes.
	select {
	case e := <-srvErrCh:
		t.Fatalf("fallback server error: %v", e)
	case got := <-recvCh:
		if !bytes.Equal(got, req) {
			t.Fatalf("mismatch: got %d bytes, want %d bytes", len(got), len(req))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for fallback server receive")
	}

	// Ensure Process ends cleanly.
	select {
	case e := <-procErrCh:
		if e != nil {
			t.Fatalf("Process returned error: %v", e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for Process to return")
	}
}
