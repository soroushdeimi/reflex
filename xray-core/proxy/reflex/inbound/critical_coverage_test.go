package inbound

import (
	"context"
	gonet "net"
	"testing"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/proxy/reflex"
)

func TestCriticalErrorPaths(t *testing.T) {
	config := &reflex.InboundConfig{
		Clients: []*reflex.User{{Id: "29525c56-6556-43f1-8b2b-09b673627038"}},
	}
	h, _ := New(context.Background(), config)
	handler := h.(*Handler)

	// --- 1. Test: Handshake Failure (Too short for Public Key) ---
	t.Run("ShortPublicKey", func(t *testing.T) {
		client, server := gonet.Pipe()
		go func() {
			client.Write([]byte{0x52, 0x46, 0x58, 0x4C}) // Magic OK
			client.Write(make([]byte, 10))             // ONLY 10 bytes (Needs 32)
			client.Close()
		}()
		mock := &MockStatConn{Conn: server}
		handler.Process(context.Background(), net.Network_TCP, mock, nil)
	})

	// --- 2. Test: Fallback Detection (HTTP GET coverage) ---
	t.Run("HTTPGetFallback", func(t *testing.T) {
		client, server := gonet.Pipe()
		go func() {
			client.Write([]byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"))
			client.Close()
		}()
		mock := &MockStatConn{Conn: server}
		handler.Process(context.Background(), net.Network_TCP, mock, nil)
	})

	// --- 3. Test: authenticateUserBytes (Unknown User) ---
	t.Run("UnknownUserAuth", func(t *testing.T) {
		var fakeID [16]byte // All zeros
		_, err := handler.authenticateUserBytes(fakeID)
		if err == nil {
			t.Error("Should have failed for unknown user")
		}
	})
}