package inbound

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

func TestSessionWriteReadFrame(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)

	writerSession, err := NewSession(key)
	if err != nil {
		t.Fatalf("NewSession(writer) failed: %v", err)
	}
	readerSession, err := NewSession(key)
	if err != nil {
		t.Fatalf("NewSession(reader) failed: %v", err)
	}

	var writer bytes.Buffer
	payload := []byte("hello-reflex")

	if err := writerSession.WriteFrame(&writer, FrameTypeData, payload); err != nil {
		t.Fatalf("WriteFrame failed: %v", err)
	}

	frame, err := readerSession.ReadFrame(&writer)
	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}

	if frame.Type != FrameTypeData {
		t.Fatalf("unexpected frame type: got %d but we want %d", frame.Type, FrameTypeData)
	}
	if !bytes.Equal(frame.Payload, payload) {
		t.Fatalf("payload mismatch: got %q but we want %q", frame.Payload, payload)
	}
}

func TestNewSessionInvalidKey(t *testing.T) {
	_, err := NewSession([]byte("short-key"))
	if err == nil {
		t.Fatal("expected error for invalid key length")
	}
}

func TestWriteFrameTooLarge(t *testing.T) {
	key := bytes.Repeat([]byte{2}, 32)
	s, err := NewSession(key)
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}

	// encrypted size is payload + 16 bytes; "this" > 65535 -> we expect an error
	huge := make([]byte, 65535)
	var writer bytes.Buffer
	if err := s.WriteFrame(&writer, FrameTypeData, huge); err == nil {
		t.Fatal("expected oversized frame error")
	}
}

func TestWriteFrameWithMorphing(t *testing.T) {
	key := bytes.Repeat([]byte{3}, 32)
	writerSession, err := NewSession(key)
	if err != nil {
		t.Fatalf("NewSession(writer) failed: %v", err)
	}
	readerSession, err := NewSession(key)
	if err != nil {
		t.Fatalf("NewSession(reader) failed: %v", err)
	}

	profile := &TrafficProfile{
		Name: "test",
		PacketSizes: []PacketSizeDist{
			{Size: 32, Weight: 1.0},
		},
	}
	writerSession.SetTrafficProfile(profile)

	var writer bytes.Buffer
	if err := writerSession.WriteFrameWithMorphing(&writer, FrameTypeData, []byte("abc")); err != nil {
		t.Fatalf("WriteFrameWithMorphing failed: %v", err)
	}

	frame, err := readerSession.ReadFrame(&writer)
	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}
	if len(frame.Payload) != 32 {
		t.Fatalf("unexpected morphed payload len: got %d we want 32", len(frame.Payload))
	}
	if string(frame.Payload[:3]) != "abc" {
		t.Fatalf("payload prefix mismatch: got %q", string(frame.Payload[:3]))
	}
}

func TestHandleControlFrameOverridesProfile(t *testing.T) {
	key := bytes.Repeat([]byte{4}, 32)
	s, err := NewSession(key)
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}

	profile := &TrafficProfile{
		Name: "test-ctrl",
		PacketSizes: []PacketSizeDist{
			{Size: 10, Weight: 1.0},
		},
		Delays: []DelayDist{
			{Delay: 1 * time.Millisecond, Weight: 1.0},
		},
	}
	s.SetTrafficProfile(profile)

	paddingPayload := make([]byte, 2)

	binary.BigEndian.PutUint16(paddingPayload, 64)
	s.HandleControlFrame(&Frame{Type: FrameTypePadding, Payload: paddingPayload})
	if got := s.profile.GetPacketSize(); got != 64 {
		t.Fatalf("padding control not applied: got %d but we want 64", got)
	}

	timingPayload := make([]byte, 8)
	binary.BigEndian.PutUint64(timingPayload, 25)
	s.HandleControlFrame(&Frame{Type: FrameTypeTiming, Payload: timingPayload})
	if got := s.profile.GetDelay(); got != 25*time.Millisecond {
		t.Fatalf("timing control not applied: got %v but we want 25ms", got)
	}
}
