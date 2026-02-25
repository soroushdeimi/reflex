package inbound

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/proxy/reflex"
)

func TestFallbackPreservesPeekedBytes(t *testing.T) {
	// Start a local TCP server as fallback target.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	port := ln.Addr().(*net.TCPAddr).Port

	cfg := &reflex.InboundConfig{
		Fallback: &reflex.Fallback{Dest: uint32(port)},
	}
	h := &Handler{config: cfg}

	// Prepare payload that simulates non-reflex traffic (e.g., TLS ClientHello-like bytes).
	payload := append([]byte{0x16, 0x03, 0x01, 0x00, 0x2f}, bytes.Repeat([]byte{0xab}, 200)...)

	recvCh := make(chan []byte, 1)
	errCh := make(chan error, 1)

	// Accept exactly one connection and read exactly len(payload) bytes, then close.
	go func() {
		c, e := ln.Accept()
		if e != nil {
			errCh <- e
			return
		}
		defer c.Close()

		buf := make([]byte, len(payload))
		_, e = io.ReadFull(c, buf)
		if e != nil {
			errCh <- e
			return
		}
		recvCh <- buf
	}()

	// net.Pipe simulates client <-> inbound conn.
	clientConn, inboundConn := net.Pipe()
	defer clientConn.Close()
	// inboundConn will be closed by handleFallback() via defer.

	// Client sends data then closes.
	go func() {
		_, _ = clientConn.Write(payload)
		_ = clientConn.Close()
	}()

	reader := bufio.NewReader(inboundConn)

	// Important: Peek to force buffering without consuming.
	if _, err := reader.Peek(64); err != nil {
		t.Fatalf("peek: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Run fallback relay (should forward all bytes including peeked ones).
	if err := h.handleFallback(ctx, reader, inboundConn); err != nil {
		t.Fatalf("handleFallback: %v", err)
	}

	// Verify the fallback server received the exact payload.
	select {
	case e := <-errCh:
		t.Fatalf("fallback server error: %v", e)
	case got := <-recvCh:
		if !bytes.Equal(got, payload) {
			t.Fatalf("payload mismatch: got %d bytes, want %d bytes", len(got), len(payload))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for fallback server receive")
	}
}
