package inbound

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func buildDestReq(addr string, port uint16, initial []byte) []byte {
	b := make([]byte, 1+len(addr)+2+len(initial))
	b[0] = byte(len(addr))
	copy(b[1:], []byte(addr))
	binary.BigEndian.PutUint16(b[1+len(addr):1+len(addr)+2], port)
	copy(b[1+len(addr)+2:], initial)
	return b
}

func TestParseDestinationRequest_OK(t *testing.T) {
	req := buildDestReq("example.com", 443, []byte("hello"))
	addr, port, initial, err := parseDestinationRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	if addr != "example.com" {
		t.Fatalf("addr mismatch: got %q want %q", addr, "example.com")
	}
	if port != 443 {
		t.Fatalf("port mismatch: got %d want %d", port, 443)
	}
	if string(initial) != "hello" {
		t.Fatalf("initial mismatch: got %q want %q", string(initial), "hello")
	}
}

func TestParseDestinationRequest_Bad(t *testing.T) {
	// too short
	if _, _, _, err := parseDestinationRequest([]byte{}); err == nil {
		t.Fatal("expected error for empty request")
	}
	// addrLen present but not enough bytes
	if _, _, _, err := parseDestinationRequest([]byte{5, 'a', 'b'}); err == nil {
		t.Fatal("expected error for short address")
	}
	// addr ok but missing port bytes
	b := append([]byte{3, 'a', 'b', 'c'}, []byte{0x01}...) // only 1 byte of port
	if _, _, _, err := parseDestinationRequest(b); err == nil {
		t.Fatal("expected error for missing port bytes")
	}
}

func TestIsTimestampFresh(t *testing.T) {
	now := time.Now().Unix()

	if !isTimestampFresh(now, 5*time.Minute) {
		t.Fatal("expected now to be fresh")
	}
	old := time.Now().Add(-10 * time.Minute).Unix()
	if isTimestampFresh(old, 5*time.Minute) {
		t.Fatal("expected old timestamp to be not fresh")
	}
	if isTimestampFresh(0, 5*time.Minute) {
		t.Fatal("expected zero timestamp to be not fresh")
	}
}

func TestIsHTTPPostLike(t *testing.T) {
	h := &Handler{}
	if !h.isHTTPPostLike([]byte("POST / HTTP/1.1\r\n")) {
		t.Fatal("expected POST-like to be true")
	}
	if h.isHTTPPostLike([]byte("GET / HTTP/1.1\r\n")) {
		t.Fatal("expected GET to be false")
	}
	if h.isHTTPPostLike([]byte("PO")) {
		t.Fatal("expected too-short to be false")
	}
}

func TestHandleFallbackWithPrefix_ForwardsPrefixAndResponse(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// ---------- fallback server ----------
	fbLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fbLn.Close() }()

	fbPort := uint32(fbLn.Addr().(*net.TCPAddr).Port)

	prefix := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n")
	rest := []byte("User-Agent: test\r\n\r\n")
	expected := append(append([]byte{}, prefix...), rest...)

	recvCh := make(chan []byte, 1)
	fbErrCh := make(chan error, 1)

	go func() {
		c, aerr := fbLn.Accept()
		if aerr != nil {
			fbErrCh <- aerr
			return
		}
		defer func() { _ = c.Close() }()

		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))

		buf := make([]byte, len(expected))
		_, rerr := io.ReadFull(c, buf)
		if rerr != nil {
			fbErrCh <- rerr
			return
		}
		recvCh <- buf

		_ = c.SetWriteDeadline(time.Now().Add(3 * time.Second))
		_, _ = c.Write([]byte("OK"))
		fbErrCh <- nil
	}()

	// ---------- incoming server (the handler runs here) ----------
	inLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = inLn.Close() }()

	h := &Handler{fallback: &FallbackConfig{Dest: fbPort}}

	done := make(chan error, 1)
	go func() {
		conn, aerr := inLn.Accept()
		if aerr != nil {
			done <- aerr
			return
		}
		defer func() { _ = conn.Close() }()

		r := bufio.NewReader(conn)

		// simulate "prefix already consumed" by a parser
		consumed := make([]byte, len(prefix))
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadFull(r, consumed); err != nil {
			done <- err
			return
		}
		_ = conn.SetReadDeadline(time.Time{})

		done <- h.handleFallbackWithPrefix(ctx, r, conn, consumed)
	}()

	// ---------- client ----------
	clientConn, err := net.Dial("tcp", inLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = clientConn.Close() }()

	if _, err := clientConn.Write(prefix); err != nil {
		t.Fatal(err)
	}
	if _, err := clientConn.Write(rest); err != nil {
		t.Fatal(err)
	}

	_ = clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp := make([]byte, 2)
	n, err := clientConn.Read(resp)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if string(resp[:n]) != "OK" {
		t.Fatalf("unexpected response: %q", string(resp[:n]))
	}

	_ = clientConn.Close() // let io.Copy exit

	// ---------- assertions ----------
	select {
	case herr := <-done:
		if herr != nil {
			t.Fatalf("handleFallbackWithPrefix returned error: %v", herr)
		}
	case <-ctx.Done():
		t.Fatalf("timeout waiting for handler: %v", ctx.Err())
	}

	select {
	case got := <-recvCh:
		if !bytes.Equal(got, expected) {
			t.Fatalf("forwarded bytes mismatch:\n got:  %q\n want: %q", string(got), string(expected))
		}
	case <-ctx.Done():
		t.Fatal("timeout waiting for fallback server receive")
	}

	if fbErr := <-fbErrCh; fbErr != nil {
		t.Fatalf("fallback server error: %v", fbErr)
	}
}
