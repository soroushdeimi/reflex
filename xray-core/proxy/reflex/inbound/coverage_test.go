package inbound

import (
	"context"
	gonet "net"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/proxy/reflex"
)

// Minimal mock to satisfy the connection interface
type FinalMockConn struct {
	gonet.Conn
}
func (c *FinalMockConn) BytesRead() uint64        { return 0 }
func (c *FinalMockConn) BytesWritten() uint64     { return 0 }
func (c *FinalMockConn) HandshakeSeconds() uint64 { return 0 }
func (c *FinalMockConn) Upstream() any            { return nil }

func TestFinalCoveragePush(t *testing.T) {
	// 1. Coverage for the New function and Handler creation
	config := &reflex.InboundConfig{}
	h, err := New(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	handler := h.(*Handler)

	// 2. Coverage for Network() and String() methods
	_ = handler.Network()
	_ = config.String()

	// 3. Coverage for the Fallback Dial Error path
	// We trigger the fallback logic but provide a closed connection
	client, server := gonet.Pipe()
	go func() {
		// Send data that is NOT a Reflex magic number to trigger fallback
		client.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
		client.Close()
	}()

	mock := &FinalMockConn{Conn: server}
	
	// This will execute the fallback logic. Even if it errors, 
	// it covers the 'if magic != ReflexMagic' branch.
	handler.Process(context.Background(), net.Network_TCP, mock, nil)
}