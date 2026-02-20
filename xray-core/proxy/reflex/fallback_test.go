package reflex

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

// MockConn implements net.Conn for testing
type MockConn struct {
	net.Conn
	readBuf  *bytes.Buffer
	writeBuf *bytes.Buffer
	closed   bool
}

func (m *MockConn) Read(b []byte) (n int, err error)  { return m.readBuf.Read(b) }
func (m *MockConn) Write(b []byte) (n int, err error) { return m.writeBuf.Write(b) }
func (m *MockConn) Close() error                      { m.closed = true; return nil }
func (m *MockConn) LocalAddr() net.Addr               { return nil }
func (m *MockConn) RemoteAddr() net.Addr              { return nil }
func (m *MockConn) SetDeadline(t time.Time) error     { return nil }

func TestFallbackConn(t *testing.T) {
	raw := &MockConn{
		readBuf:  bytes.NewBuffer([]byte("real-data")),
		writeBuf: &bytes.Buffer{},
	}

	// Buffer with peeked data
	peeked := []byte("peeked-")
	// Combine peeked data and raw data
	br := bufio.NewReader(io.MultiReader(bytes.NewReader(peeked), raw))
	fc := NewFallbackConn(br, raw)

	// Test Read (should include peeked data)
	expected := "peeked-real-data"
	buf := make([]byte, len(expected))

	// Use io.ReadFull to ensure we get all staged data from bufio
	n, err := io.ReadFull(fc, buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if string(buf[:n]) != expected {
		t.Errorf("Read content mismatch: got [%s], expected [%s]", string(buf[:n]), expected)
	}

	// Test Write
	data := []byte("to-server")
	_, err = fc.Write(data)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if raw.writeBuf.String() != "to-server" {
		t.Errorf("Write data mismatch: got %s", raw.writeBuf.String())
	}

	// Test Close
	fc.Close()
	if !raw.closed {
		t.Error("Close was not propagated to raw connection")
	}

	// Test Read after close
	retryBuf := make([]byte, 16)
	_, err = fc.Read(retryBuf)
	if err != io.EOF {
		t.Errorf("Expected EOF after close, got %v", err)
	}
}

func TestTeeReader(t *testing.T) {
	src := bytes.NewReader([]byte("hello"))
	dst := &bytes.Buffer{}
	tr := NewTeeReader(src, dst)

	p := make([]byte, 5)
	n, _ := tr.Read(p)

	if n != 5 || dst.String() != "hello" {
		t.Error("TeeReader failed to mirror data")
	}
}

func TestForwardConnection(t *testing.T) {
	c1_client, c1_server := net.Pipe()
	c2_client, c2_server := net.Pipe()

	go ForwardConnection(c1_server, c2_server)

	// Test data flow c1 -> c2
	msg := []byte("test-msg")
	go c1_client.Write(msg)

	buf := make([]byte, 8)
	io.ReadFull(c2_client, buf)
	if string(buf) != string(msg) {
		t.Errorf("Forwarding failed: %s", string(buf))
	}

	c1_client.Close()
	c2_client.Close()
}
