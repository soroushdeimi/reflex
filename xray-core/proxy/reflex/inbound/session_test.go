package inbound

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"testing"
)

func testKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i + 1)
	}
	return k
}

func TestSessionWriteReadFrame(t *testing.T) {
	writerSession, err := NewSession(testKey())
	if err != nil {
		t.Fatal(err)
	}
	readerSession, err := NewSession(testKey())
	if err != nil {
		t.Fatal(err)
	}

	var wire bytes.Buffer
	payload := []byte("hello reflex")
	if err := writerSession.WriteFrame(&wire, FrameTypeData, payload); err != nil {
		t.Fatal(err)
	}

	frame, err := readerSession.ReadFrame(&wire)
	if err != nil {
		t.Fatal(err)
	}
	if frame.Type != FrameTypeData {
		t.Fatalf("unexpected frame type: %d", frame.Type)
	}
	if !bytes.Equal(frame.Payload, payload) {
		t.Fatalf("payload mismatch: got=%q want=%q", frame.Payload, payload)
	}
}

func TestSessionReplayDetection(t *testing.T) {
	writerSession, err := NewSession(testKey())
	if err != nil {
		t.Fatal(err)
	}
	readerSession, err := NewSession(testKey())
	if err != nil {
		t.Fatal(err)
	}

	var wire bytes.Buffer
	if err := writerSession.WriteFrame(&wire, FrameTypeData, []byte("abc")); err != nil {
		t.Fatal(err)
	}
	frameBytes := append([]byte(nil), wire.Bytes()...)

	if _, err := readerSession.ReadFrame(bytes.NewReader(frameBytes)); err != nil {
		t.Fatalf("first read failed: %v", err)
	}

	_, err = readerSession.ReadFrame(bytes.NewReader(frameBytes))
	if err == nil {
		t.Fatal("expected replay detection error")
	}
	if !strings.Contains(err.Error(), "replay") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEmptyData(t *testing.T) {
	s, err := NewSession(testKey())
	if err != nil {
		t.Fatal(err)
	}
	var wire bytes.Buffer
	if err := s.WriteFrame(&wire, FrameTypeData, []byte{}); err != nil {
		t.Fatalf("empty payload should not crash: %v", err)
	}
}

func TestLargeData(t *testing.T) {
	s, err := NewSession(testKey())
	if err != nil {
		t.Fatal(err)
	}
	var wire bytes.Buffer
	large := make([]byte, 10*1024*1024)
	if err := s.WriteFrame(&wire, FrameTypeData, large); err == nil {
		t.Fatal("expected oversized frame error")
	}
}

func TestClosedConnection(t *testing.T) {
	s, err := NewSession(testKey())
	if err != nil {
		t.Fatal(err)
	}
	c1, c2 := net.Pipe()
	_ = c2.Close()
	if err := s.WriteFrame(c1, FrameTypeData, []byte("test")); err == nil {
		t.Fatal("expected write error on closed connection")
	}
	_ = c1.Close()
}

func BenchmarkEncryption(b *testing.B) {
	s, err := NewSession(testKey())
	if err != nil {
		b.Fatal(err)
	}
	data := make([]byte, 1024)
	var wire bytes.Buffer
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		wire.Reset()
		if err := s.WriteFrame(&wire, FrameTypeData, data); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncryptionSizes(b *testing.B) {
	sizes := []int{64, 256, 1024, 4096, 16384}
	for _, size := range sizes {
		b.Run(fmt.Sprintf("%d", size), func(b *testing.B) {
			s, err := NewSession(testKey())
			if err != nil {
				b.Fatal(err)
			}
			data := make([]byte, size)
			var wire bytes.Buffer
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				wire.Reset()
				if err := s.WriteFrame(&wire, FrameTypeData, data); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkMemoryAllocation(b *testing.B) {
	s, err := NewSession(testKey())
	if err != nil {
		b.Fatal(err)
	}
	data := make([]byte, 1024)
	var wire bytes.Buffer
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		wire.Reset()
		if err := s.WriteFrame(&wire, FrameTypeData, data); err != nil {
			b.Fatal(err)
		}
	}
}
