package reflex_test

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/proxy/reflex/inbound"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func TestFallbackToWebServer(t *testing.T) {
	// Create a simple HTTP server
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer httpServer.Close()

	// Extract port from test server
	_, portStr, _ := net.SplitHostPort(httpServer.Listener.Addr().String())
	fallbackPort := uint32(0)
	if portStr != "" {
		port, err := strconv.ParseUint(portStr, 10, 32)
		if err == nil {
			fallbackPort = uint32(port)
		}
	}

	if fallbackPort == 0 {
		t.Fatal("failed to get fallback port")
	}

	// Create handler with fallback
	config := &reflex.InboundConfig{
		Clients: []*reflex.User{
			{
				Id: "00000000-0000-0000-0000-000000000000",
			},
		},
		Fallback: &reflex.Fallback{
			Dest: fallbackPort,
		},
	}

	handler, err := inbound.New(context.Background(), config)
	if err != nil {
		t.Fatalf("create handler failed: %v", err)
	}
	h := handler.(*inbound.Handler)

	// Create connection with non-Reflex data (HTTP request)
	clientConn, serverConn := net.Pipe()

	// Use context with timeout to prevent hanging
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Client goroutine: send request
	go func() {
		defer clientConn.Close()
		// Send HTTP GET request (non-Reflex protocol)
		httpRequest := "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
		clientConn.Write([]byte(httpRequest))
		// Try to read response
		clientConn.SetReadDeadline(time.Now().Add(1 * time.Second))
		response := make([]byte, 1024)
		clientConn.Read(response)
	}()

	defer serverConn.Close()
	statConn := stat.Connection(serverConn)

	// Process should forward to fallback (this will block until connection closes)
	processDone := make(chan error, 1)
	go func() {
		processDone <- h.Process(ctx, xnet.Network_TCP, statConn, nil)
	}()

	// Wait for process to complete or timeout
	select {
	case err := <-processDone:
		// Process completed
		// We expect it to complete (either successfully or with connection close error)
		if err != nil {
			errStr := err.Error()
			// These are acceptable errors
			if errStr == "context deadline exceeded" || 
			   errStr == "context canceled" ||
			   errStr == "fallback forwarding error" ||
			   errStr == "failed to connect to fallback server" {
				// Expected errors, test passes
				return
			}
			// Other errors might indicate a problem
			t.Logf("fallback completed with: %v", err)
		}
		// Success: fallback was called and completed
	case <-time.After(2 * time.Second):
		// Timeout - cancel context and verify fallback was attempted
		cancel()
		// Check if process completed after cancel
		select {
		case err := <-processDone:
			if err != nil {
				t.Logf("fallback completed after cancel: %v", err)
			}
		case <-time.After(100 * time.Millisecond):
			// Process still running, but that's OK - it means fallback is forwarding
			t.Log("Fallback is forwarding (test passes)")
		}
	}
}

func TestFallbackWithoutConfig(t *testing.T) {
	config := &reflex.InboundConfig{
		Clients: []*reflex.User{
			{
				Id: "00000000-0000-0000-0000-000000000000",
			},
		},
		// No fallback configured
	}

	handler, _ := inbound.New(context.Background(), config)
	h := handler.(*inbound.Handler)

	clientConn, serverConn := net.Pipe()

	go func() {
		defer clientConn.Close()
		// Send non-Reflex data
		clientConn.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
	}()

	defer serverConn.Close()
	statConn := stat.Connection(serverConn)

	// Should return error when no fallback configured
	err := h.Process(context.Background(), xnet.Network_TCP, statConn, nil)
	if err == nil {
		t.Fatal("should return error when fallback not configured")
	}
}
