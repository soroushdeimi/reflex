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
	br := bufio.NewReader(io.MultiReader(bytes.NewReader(peeked), raw))

	fc := NewFallbackConn(br, raw)

	// Test Read (should include peeked data)
	buf := make([]byte, 16)
	n, err := fc.Read(buf)
	if err != nil || string(buf[:n]) != "peeked-real-data" {
		t.Errorf("Read failed: got %s", string(buf[:n]))
	}

	// Test Write
	data := []byte("to-server")
	fc.Write(data)
	if raw.writeBuf.String() != "to-server" {
		t.Errorf("Write failed")
	}

	// Test Close
	fc.Close()
	if !raw.closed {
		t.Error("Close was not propagated")
	}

	// Test Read after close
	_, err = fc.Read(buf)
	if err != io.EOF {
		t.Error("Expected EOF after close")
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
