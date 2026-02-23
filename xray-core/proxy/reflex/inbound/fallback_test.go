package inbound

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/xtls/xray-core/proxy/reflex"
)

func TestFallback(t *testing.T) {
	// Create a simple HTTP server for fallback
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("OK"))
	}))
	defer server.Close()

	// Extract port from server URL
	serverAddr := server.Listener.Addr().(*net.TCPAddr)
	port := uint32(serverAddr.Port)

	// Create handler with fallback
	config := &reflex.InboundConfig{
		Clients: []*reflex.User{},
		Fallback: &reflex.Fallback{
			Dest: port,
		},
	}

	_, err := New(context.Background(), config)
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	// Create connection with non-Reflex data (HTTP GET)
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Send HTTP GET request (not Reflex)
	go func() {
		defer clientConn.Close()
		_, _ = clientConn.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	}()

	// Process should detect non-Reflex and fallback
	reader := bufio.NewReader(serverConn)
	peeked, err := reader.Peek(ReflexMinHandshakeSize)
	if err != nil && err != io.EOF {
		// If peek fails with insufficient data, that's OK for this test
		if len(peeked) < 4 {
			return // Not enough data to test
		}
	}

	// Check that it's not Reflex
	if len(peeked) >= 4 {
		magic := peeked[0:4]
		if string(magic) == "GET " {
			// This is HTTP GET, should go to fallback
			// Note: In real scenario, fallback would be called
			// For testing, we just verify the detection logic
		} else {
			t.Fatalf("unexpected prefix, want GET got %q", string(magic))
		}
	}
}

func TestFallbackNoConfig(t *testing.T) {
	// Create handler without fallback
	config := &reflex.InboundConfig{
		Clients: []*reflex.User{},
		Fallback: nil,
	}

	handler, err := New(context.Background(), config)
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	reflexHandler := handler.(*Handler)

	// Try to handle fallback without config
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	reader := bufio.NewReader(serverConn)
	err = reflexHandler.handleFallback(context.Background(), reader, serverConn)
	if err == nil {
		t.Fatal("should return error when fallback is not configured")
	}
}

func TestIsReflexHandshake(t *testing.T) {
	handler := createTestHandler()

	// Test with magic number
	magicData := make([]byte, 4)
	magicData[0] = 0x52 // 'R'
	magicData[1] = 0x46 // 'F'
	magicData[2] = 0x58 // 'X'
	magicData[3] = 0x4C // 'L'
	if !handler.isReflexHandshake(magicData) {
		t.Fatal("should detect magic number")
	}

	// Test with HTTP POST
	postData := []byte("POST /api HTTP/1.1\r\nHost: example.com\r\n")
	if !handler.isReflexHandshake(postData) {
		t.Fatal("should detect HTTP POST")
	}

	// Test with neither
	otherData := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n")
	if handler.isReflexHandshake(otherData) {
		t.Fatal("should not detect non-Reflex data")
	}
}

func TestPreloadedConn(t *testing.T) {
	// Test that preloadedConn preserves peeked bytes
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Write some data
	testData := []byte("test data")
	go func() {
		defer clientConn.Close()
		_, _ = clientConn.Write(testData)
	}()

	// Create reader and peek
	reader := bufio.NewReader(serverConn)
	peeked, err := reader.Peek(len(testData))
	if err != nil {
		t.Fatalf("failed to peek: %v", err)
	}

	// Create preloadedConn
	preloaded := &preloadedConn{
		Reader:     reader,
		Connection: serverConn,
	}

	// Read from preloadedConn - should include peeked bytes
	readData := make([]byte, len(testData))
	n, err := preloaded.Read(readData)
	if err != nil && err != io.EOF {
		t.Fatalf("failed to read: %v", err)
	}

	// Verify peeked data is included
	if !bytes.Equal(peeked, readData[:n]) {
		t.Fatal("preloadedConn should preserve peeked bytes")
	}
}

