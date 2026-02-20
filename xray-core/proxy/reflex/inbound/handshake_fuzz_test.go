package inbound

import (
	"bufio"
	"bytes"
	"context"
	"io"
	stdnet "net"
	"testing"

	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/reflex"
)

func FuzzInboundProcess(f *testing.F) {
	// Seed with valid magic and truncated handshakes
	f.Add([]byte{0x52, 0x46, 0x58, 0x4C})
	f.Add([]byte("POST /api HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	f.Add(make([]byte, 100))

	u := uuid.New()
	config := &reflex.InboundConfig{
		Clients: []*reflex.User{{Id: u.String()}},
	}
	h, _ := New(context.Background(), config)
	handler := h.(*Handler)

	f.Fuzz(func(t *testing.T, data []byte) {
		reader := bufio.NewReader(bytes.NewReader(data))
		// Mock connection
		conn := &MockConnection{Conn: &fuzzConn{Reader: bytes.NewReader(data)}}
		// This might return error, but should NOT panic
		_ = handler.processWithReader(context.Background(), reader, conn, nil)
	})
}

type fuzzConn struct {
	io.Reader
	stdnet.Conn
}

func (c *fuzzConn) Read(b []byte) (int, error) {
	return c.Reader.Read(b)
}

func (c *fuzzConn) Write(b []byte) (int, error) {
	return len(b), nil
}

func (c *fuzzConn) Close() error { return nil }
