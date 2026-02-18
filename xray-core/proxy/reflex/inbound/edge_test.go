package inbound

import (
	"context"
	"io"
	gonet "net"
	"testing"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/proxy/reflex"
)

// Reference: testing.md "Test Edge Cases"

// 1. Test with closed connection
func TestClosedConnection(t *testing.T) {
	// Setup a session
	key := make([]byte, 32)
	session, _ := reflex.NewSession(key)
	
	conn, _ := gonet.Pipe()
	conn.Close() // Close immediately
	
	// Write should fail
	err := session.WriteFrame(conn, reflex.FrameTypeData, []byte("test"))
	if err == nil {
		t.Error("WriteFrame on closed connection should return error")
	}
}

// 2. Test with incomplete handshake (Connection closed mid-handshake)
func TestIncompleteHandshake(t *testing.T) {
	config := &reflex.InboundConfig{
		Clients: []*reflex.User{{Id: "29525c56-6556-43f1-8b2b-09b673627038"}},
	}
	h, _ := New(context.Background(), config)
	handler := h.(*Handler)

	client, server := gonet.Pipe()
	
	go func() {
		// Send just the Magic Bytes, then close
		client.Write([]byte{0x52, 0x46, 0x58, 0x4C}) 
		// Missing Public Key, UserID, etc.
		client.Close()
	}()

	mock := &MockStatConn{Conn: server}
	err := handler.Process(context.Background(), net.Network_TCP, mock, nil)
	
	// Should fail cleanly, not panic
	if err == nil {
		t.Error("Should return error for incomplete handshake")
	}
}

// 3. Test with connection reset (Drop mid-transfer)
func TestConnectionReset(t *testing.T) {
	key := make([]byte, 32)
	session, _ := reflex.NewSession(key)
	client, server := gonet.Pipe()

	// Start reading in background
	go func() {
		buf := make([]byte, 1024)
		server.Read(buf)
		server.Close() // Close mid-transfer
	}()

	// Write data
	err := session.WriteFrame(client, reflex.FrameTypeData, []byte("test data"))
	// Depending on timing, this might succeed (buffered) or fail. 
	// The important part is it doesn't panic.
	if err != nil {
		t.Log("Write failed as expected (or succeeded before close)")
	}
}

// 4. Test with oversized payload
func TestOversizedPayload(t *testing.T) {
	key := make([]byte, 32)
	session, _ := reflex.NewSession(key)
	
	// Create dummy writer that discards data
	writer := io.Discard
	
	// Huge data (10MB)
	hugeData := make([]byte, 10*1024*1024)
	
	// Should split or handle it
	err := session.WriteFrame(writer, reflex.FrameTypeData, hugeData)
	if err != nil {
		t.Log("Oversized payload rejected (Acceptable behavior)")
	} else {
		t.Log("Oversized payload handled (Acceptable behavior)")
	}
}

// 5. Test with Invalid Handshake (Garbage data)
func TestInvalidHandshake(t *testing.T) {
	config := &reflex.InboundConfig{
		Clients: []*reflex.User{{Id: "29525c56-6556-43f1-8b2b-09b673627038"}},
	}
	h, _ := New(context.Background(), config)
	handler := h.(*Handler)

	client, server := gonet.Pipe()
	
	go func() {
		client.Write([]byte("INVALID DATA STREAM"))
		client.Close()
	}()

	mock := &MockStatConn{Conn: server}
	err := handler.Process(context.Background(), net.Network_TCP, mock, nil)
	
	if err == nil {
		t.Error("Should reject invalid handshake data")
	}
}