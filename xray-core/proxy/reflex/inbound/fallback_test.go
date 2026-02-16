package inbound

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestIsReflexHandshakeByMagic(t *testing.T) {
	h := &Handler{}
	data := make([]byte, 8)
	binary.BigEndian.PutUint32(data[:4], ReflexMagic)

	if !h.isReflexHandshake(data) {
		t.Fatal("expected magic handshake detection")
	}
}

func TestIsReflexHandshakeByHTTPPost(t *testing.T) {
	h := &Handler{}
	data := []byte("POST /api HTTP/1.1\r\nHost: test\r\n\r\n")
	if !h.isReflexHandshake(data) {
		t.Fatal("expected HTTP POST handshake detection")
	}
}

func TestPreservesPeekedBytes(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	go func() {
		_, _ = client.Write([]byte("HELLO-WORLD"))
	}()

	reader := bufio.NewReader(server)
	peeked, err := reader.Peek(5)
	if err != nil {
		t.Fatalf("Peek failed: %v", err)
	}
	if string(peeked) != "HELLO" {
		t.Fatalf("unexpected peeked bytes: %q", string(peeked))
	}

	pc := &preloadedConn{
		Reader:     reader,
		Connection: server,
	}

	got := make([]byte, len("HELLO-WORLD"))
	if _, err := pc.Read(got); err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if string(got) != "HELLO-WORLD" {
		t.Fatalf("expected full payload after peek but got %q", string(got))
	}
}

func TestHandleFallbackDenyWrites403(t *testing.T) {
	h := &Handler{}
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	done := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 256)
		_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _ := client.Read(buf)
		done <- buf[:n]
	}()

	if err := h.handleFallbackDeny(server); err != nil {
		t.Fatalf("handleFallbackDeny failed: %v", err)
	}

	respRaw := <-done
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(respRaw)), nil)
	if err != nil {
		t.Fatalf("failed to parse HTTP response: %v, raw=%q", err, string(respRaw))
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d (status=%q)", http.StatusForbidden, resp.StatusCode, resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed reading response body: %v", err)
	}
	// didn't want to assert exact body content since it may be different in different languages or future etc ... so didn't get really strict about it
	if len(bytes.TrimSpace(body)) == 0 {
		t.Fatal("expected non-empty deny response body")
	}
}
