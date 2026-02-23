package inbound

import (
	"bytes"
	"io"
	"testing"
)

func BenchmarkSessionWriteFrame(b *testing.B) {
	sess, err := createTestSession()
	if err != nil {
		b.Fatalf("failed to create session: %v", err)
	}

	payload := bytes.Repeat([]byte("a"), 1024)
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := sess.WriteFrame(io.Discard, FrameTypeData, payload); err != nil {
			b.Fatalf("write frame failed: %v", err)
		}
	}
}

func BenchmarkSessionWriteFrameWithMorphing(b *testing.B) {
	sess, err := createTestSession()
	if err != nil {
		b.Fatalf("failed to create session: %v", err)
	}

	profile := GetProfileByName("youtube")
	profile.SetNextDelay(0) // avoid sleep inside benchmark loop
	payload := bytes.Repeat([]byte("b"), 1200)

	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		profile.SetNextDelay(0)
		if err := sess.WriteFrameWithMorphing(io.Discard, FrameTypeData, payload, profile); err != nil {
			b.Fatalf("write frame with morphing failed: %v", err)
		}
	}
}

func BenchmarkSessionReadFrame(b *testing.B) {
	key := bytes.Repeat([]byte{0x11}, 32)
	writerSess, err := NewSession(key)
	if err != nil {
		b.Fatalf("failed to create writer session: %v", err)
	}

	payload := bytes.Repeat([]byte("c"), 1024)
	var frameBytes bytes.Buffer
	if err := writerSess.WriteFrame(&frameBytes, FrameTypeData, payload); err != nil {
		b.Fatalf("failed to prebuild frame: %v", err)
	}
	raw := frameBytes.Bytes()

	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		readerSess, err := NewSession(key)
		if err != nil {
			b.Fatalf("failed to create reader session: %v", err)
		}
		if _, err := readerSess.ReadFrame(bytes.NewReader(raw)); err != nil {
			b.Fatalf("read frame failed: %v", err)
		}
	}
}

