package tunnel

import (
	"io"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
)

// DataFrameWriter adapts a Session + io.Writer into a buf.Writer.
// It encrypts any incoming MultiBuffer into DATA frames.
type DataFrameWriter struct {
	sess *Session
	w    io.Writer
}

// NewDataFrameWriter creates a buf.Writer that emits encrypted DATA frames onto w.
func NewDataFrameWriter(sess *Session, w io.Writer) (*DataFrameWriter, error) {
	if sess == nil {
		return nil, errors.New("reflex tunnel: nil session")
	}
	if w == nil {
		return nil, errors.New("reflex tunnel: nil writer")
	}
	return &DataFrameWriter{sess: sess, w: w}, nil
}

// WriteMultiBuffer implements buf.Writer.
// This method takes ownership of mb.
func (dw *DataFrameWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)

	if dw == nil || dw.sess == nil || dw.w == nil {
		return errors.New("reflex tunnel: invalid DataFrameWriter")
	}
	if mb.IsEmpty() {
		return nil
	}

	for _, b := range mb {
		if b == nil || b.IsEmpty() {
			continue
		}
		data := b.Bytes()

		// Split if needed (defensive; typical buf.Size is 8192 < MaxPlaintextLen).
		for len(data) > 0 {
			n := len(data)
			if n > MaxPlaintextLen {
				n = MaxPlaintextLen
			}
			if err := dw.sess.WriteFrame(dw.w, FrameTypeData, data[:n]); err != nil {
				return err
			}
			data = data[n:]
		}
	}

	return nil
}

// DataFrameReader adapts a Session + io.Reader into a buf.Reader.
// It reads encrypted frames from r and only yields DATA frames as MultiBuffer.
// Padding/Timing are ignored. Close ends the stream with io.EOF.
type DataFrameReader struct {
	sess *Session
	r    io.Reader
}

// NewDataFrameReader creates a buf.Reader that decodes encrypted DATA frames from r.
func NewDataFrameReader(sess *Session, r io.Reader) (*DataFrameReader, error) {
	if sess == nil {
		return nil, errors.New("reflex tunnel: nil session")
	}
	if r == nil {
		return nil, errors.New("reflex tunnel: nil reader")
	}
	return &DataFrameReader{sess: sess, r: r}, nil
}

// ReadMultiBuffer implements buf.Reader.
func (dr *DataFrameReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if dr == nil || dr.sess == nil || dr.r == nil {
		return nil, errors.New("reflex tunnel: invalid DataFrameReader")
	}

	for {
		f, err := dr.sess.ReadFrame(dr.r)
		if err != nil {
			return nil, err
		}

		switch f.Type {
		case FrameTypeData:
			// Convert plaintext bytes to managed MultiBuffer.
			if len(f.Payload) == 0 {
				// Empty data frame: ignore and continue.
				continue
			}
			mb := buf.MergeBytes(nil, f.Payload)
			return mb, nil

		case FrameTypePadding, FrameTypeTiming:
			// Ignore and keep reading.
			continue

		case FrameTypeClose:
			return nil, io.EOF

		default:
			return nil, errors.New("reflex tunnel: unknown frame type")
		}
	}
}

// CopyToEncryptedConn copies from a buf.Reader (usually link.Reader) to an encrypted conn as DATA frames.
func CopyToEncryptedConn(sess *Session, conn io.Writer, r buf.Reader) error {
	dw, err := NewDataFrameWriter(sess, conn)
	if err != nil {
		return err
	}
	return buf.Copy(r, dw)
}

// CopyFromEncryptedConn copies from an encrypted conn (DATA frames) into a buf.Writer (usually link.Writer).
func CopyFromEncryptedConn(sess *Session, conn io.Reader, w buf.Writer) error {
	dr, err := NewDataFrameReader(sess, conn)
	if err != nil {
		return err
	}
	return buf.Copy(dr, w)
}

// WriteClose sends a CLOSE frame.
func WriteClose(sess *Session, conn io.Writer) error {
	if sess == nil {
		return errors.New("reflex tunnel: nil session")
	}
	if conn == nil {
		return errors.New("reflex tunnel: nil writer")
	}
	return sess.WriteFrame(conn, FrameTypeClose, nil)
}
