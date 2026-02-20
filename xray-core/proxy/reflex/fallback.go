package reflex

import (
	"bufio"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// FallbackConn wraps a connection with preloaded data
type FallbackConn struct {
	reader  *bufio.Reader
	rawConn net.Conn
	closed  int32
	mu      sync.Mutex
}

// NewFallbackConn creates fallback connection wrapper
func NewFallbackConn(reader *bufio.Reader, rawConn net.Conn) *FallbackConn {
	return &FallbackConn{
		reader:  reader,
		rawConn: rawConn,
		closed:  0,
	}
}

// Read reads from buffered reader (includes peeked data)
func (fc *FallbackConn) Read(b []byte) (int, error) {
	if atomic.LoadInt32(&fc.closed) != 0 {
		return 0, io.EOF
	}
	return fc.reader.Read(b)
}

// Write writes to raw connection
func (fc *FallbackConn) Write(b []byte) (int, error) {
	if atomic.LoadInt32(&fc.closed) != 0 {
		return 0, io.ErrClosedPipe
	}
	return fc.rawConn.Write(b)
}

// Close closes the connection
func (fc *FallbackConn) Close() error {
	atomic.StoreInt32(&fc.closed, 1)
	return fc.rawConn.Close()
}

// LocalAddr returns local address
func (fc *FallbackConn) LocalAddr() net.Addr {
	return fc.rawConn.LocalAddr()
}

// RemoteAddr returns remote address
func (fc *FallbackConn) RemoteAddr() net.Addr {
	return fc.rawConn.RemoteAddr()
}

// SetDeadline sets deadline
func (fc *FallbackConn) SetDeadline(t time.Time) error {
	return fc.rawConn.SetDeadline(t)
}

// SetReadDeadline sets read deadline
func (fc *FallbackConn) SetReadDeadline(t time.Time) error {
	return fc.rawConn.SetReadDeadline(t)
}

// SetWriteDeadline sets write deadline
func (fc *FallbackConn) SetWriteDeadline(t time.Time) error {
	return fc.rawConn.SetWriteDeadline(t)
}

// ForwardConnection forwards connection between two endpoints
func ForwardConnection(src, dst net.Conn) error {
	errs := make(chan error, 2)

	go func() {
		_, err := io.Copy(dst, src)
		errs <- err
	}()

	go func() {
		_, err := io.Copy(src, dst)
		errs <- err
	}()

	// Wait for first error or both done
	err1 := <-errs
	if err1 != nil && err1 != io.EOF {
		return err1
	}

	err2 := <-errs
	if err2 != nil && err2 != io.EOF {
		return err2
	}

	return nil
}

// TeeReader creates a reader that writes to writer while reading
type TeeReader struct {
	reader io.Reader
	writer io.Writer
}

// NewTeeReader creates tee reader
func NewTeeReader(reader io.Reader, writer io.Writer) *TeeReader {
	return &TeeReader{
		reader: reader,
		writer: writer,
	}
}

// Read reads and writes to writer
func (tr *TeeReader) Read(b []byte) (int, error) {
	n, err := tr.reader.Read(b)
	if n > 0 {
		tr.writer.Write(b[:n])
	}
	return n, err
}
