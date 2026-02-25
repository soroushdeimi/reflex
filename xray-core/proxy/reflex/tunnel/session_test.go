package tunnel

import (
	"bytes"
	"crypto/rand"
	"net"
	"testing"
)

func TestSessionRoundTrip(t *testing.T) {
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

	wantPayload := []byte("hello reflex")

	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := sA.WriteFrame(c1, FrameTypeData, wantPayload); err != nil {
			t.Errorf("WriteFrame: %v", err)
			return
		}
	}()

	f, err := sB.ReadFrame(c2)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	<-done

	if f.Type != FrameTypeData {
		t.Fatalf("type: got %d want %d", f.Type, FrameTypeData)
	}
	if !bytes.Equal(f.Payload, wantPayload) {
		t.Fatalf("payload mismatch: got %q want %q", string(f.Payload), string(wantPayload))
	}
}

func TestSessionTamper(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand key: %v", err)
	}

	sWrite, _ := NewSession(key)
	sRead, _ := NewSession(key)

	var buf bytes.Buffer
	if err := sWrite.WriteFrame(&buf, FrameTypeData, []byte("secret")); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}

	data := buf.Bytes()
	if len(data) < FrameHeaderLen+1 {
		t.Fatalf("unexpected encoded size: %d", len(data))
	}
	// Flip one byte in ciphertext.
	data[FrameHeaderLen] ^= 0xFF

	if _, err := sRead.ReadFrame(bytes.NewReader(data)); err == nil {
		t.Fatalf("expected decrypt error, got nil")
	}
}

func TestSessionPayloadTooLarge(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand key: %v", err)
	}
	s, _ := NewSession(key)

	big := make([]byte, MaxPlaintextLen+1)
	var buf bytes.Buffer
	if err := s.WriteFrame(&buf, FrameTypeData, big); err == nil {
		t.Fatalf("expected error for oversized payload")
	}
}
