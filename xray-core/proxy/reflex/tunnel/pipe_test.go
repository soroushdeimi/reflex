package tunnel

import (
	"bytes"
	"crypto/rand"
	"net"
	"testing"

	"github.com/xtls/xray-core/common/buf"
)

func TestPipe_DataFrameWriterAndReader(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand key: %v", err)
	}

	sA, err := NewSession(key)
	if err != nil {
		t.Fatalf("NewSession A: %v", err)
	}
	sB, err := NewSession(key)
	if err != nil {
		t.Fatalf("NewSession B: %v", err)
	}

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	// Make a payload large enough to span multiple buffers.
	want := bytes.Repeat([]byte("abcdEFGH"), 4000) // 32KB

	mb := buf.MergeBytes(nil, want)

	done := make(chan struct{})
	go func() {
		defer close(done)
		dw, err := NewDataFrameWriter(sA, c1)
		if err != nil {
			t.Errorf("NewDataFrameWriter: %v", err)
			return
		}
		if err := dw.WriteMultiBuffer(mb); err != nil {
			t.Errorf("WriteMultiBuffer: %v", err)
			return
		}
		_ = WriteClose(sA, c1)
		_ = c1.Close()
	}()

	dr, err := NewDataFrameReader(sB, c2)
	if err != nil {
		t.Fatalf("NewDataFrameReader: %v", err)
	}

	var got []byte
	for {
		m, rerr := dr.ReadMultiBuffer()
		if rerr != nil {
			if rerr.Error() == "EOF" {
				break
			}
			// net.Pipe returns io.EOF; compare as string-safe fallback.
			if rerr == nil {
				break
			}
			if rerr != nil && rerr.Error() == "EOF" {
				break
			}
			// Prefer direct EOF check:
			// (we avoid importing io here to keep test small)
			if rerr != nil && rerr.Error() == "io: read/write on closed pipe" {
				break
			}
			if rerr != nil && rerr.Error() == "closed" {
				break
			}
			// Most correct:
			if rerr != nil && rerr.Error() == "EOF" {
				break
			}
			// If not EOF:
			if rerr != nil && rerr.Error() != "EOF" {
				t.Fatalf("ReadMultiBuffer err: %v", rerr)
			}
			break
		}
		if !m.IsEmpty() {
			tmp := make([]byte, m.Len())
			m.Copy(tmp)
			got = append(got, tmp...)
		}
		buf.ReleaseMulti(m)
	}

	<-done

	if !bytes.Equal(got, want) {
		t.Fatalf("payload mismatch: got=%d want=%d", len(got), len(want))
	}
}

func TestDataFrameReader_IgnoresPaddingAndTiming(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand key: %v", err)
	}

	sA, _ := NewSession(key)
	sB, _ := NewSession(key)

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	want := []byte("hello")

	go func() {
		_ = sA.WriteFrame(c1, FrameTypePadding, []byte("xxxxx"))
		_ = sA.WriteFrame(c1, FrameTypeTiming, []byte("yyyyy"))
		_ = sA.WriteFrame(c1, FrameTypeData, want)
		_ = WriteClose(sA, c1)
		_ = c1.Close()
	}()

	dr, err := NewDataFrameReader(sB, c2)
	if err != nil {
		t.Fatalf("NewDataFrameReader: %v", err)
	}

	mb, err := dr.ReadMultiBuffer()
	if err != nil {
		t.Fatalf("ReadMultiBuffer: %v", err)
	}
	defer buf.ReleaseMulti(mb)

	got := make([]byte, mb.Len())
	mb.Copy(got)

	if !bytes.Equal(got, want) {
		t.Fatalf("got %q want %q", string(got), string(want))
	}
}
