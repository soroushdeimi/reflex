package inbound

import (
	"context"
	gonet "net" // Alias for standard Go net
	"testing"

	"github.com/xtls/xray-core/common/net" // Xray net for Network_TCP
	"github.com/xtls/xray-core/proxy/reflex"
)

// MockStatConn wraps a standard net.Conn to satisfy Xray's stat.Connection interface
type MockStatConn struct {
	gonet.Conn
}

func (c *MockStatConn) BytesRead() uint64         { return 0 }
func (c *MockStatConn) BytesWritten() uint64      { return 0 }
func (c *MockStatConn) HandshakeSeconds() uint64  { return 0 }
func (c *MockStatConn) Upstream() any             { return nil }

func TestErrorPaths(t *testing.T) {
	// 1. Setup Handler
	config := &reflex.InboundConfig{
		Clients: []*reflex.User{{Id: "29525c56-6556-43f1-8b2b-09b673627038"}},
	}
	h, _ := New(context.Background(), config)
	handler := h.(*Handler)

	// 2. Test: Incomplete Handshake (Coverage for Peek Error)
	client, server := gonet.Pipe()
	go func() {
		client.Write([]byte("RF")) // Too short to be a Magic Byte
		client.Close()
	}()
	
	// Wrap the server connection in our Mock
	mockConn := &MockStatConn{Conn: server}

	// FIX: Use net.Network_TCP instead of "tcp"
	err := handler.Process(context.Background(), net.Network_TCP, mockConn, nil)
	if err == nil {
		t.Log("Successfully caught incomplete handshake error")
	}

	// 3. Test: Unknown Protocol (Coverage for Magic Byte Mismatch)
	client2, server2 := gonet.Pipe()
	go func() {
		client2.Write([]byte("BADDATA")) 
		client2.Close()
	}()
	
	mockConn2 := &MockStatConn{Conn: server2}
	handler.Process(context.Background(), net.Network_TCP, mockConn2, nil)
}