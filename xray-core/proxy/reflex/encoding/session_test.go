package encoding

import (
	"bytes"
	"testing"
)

func TestNewSession(t *testing.T) {
	var key [32]byte
	copy(key[:], []byte("test-key-123456789012345678901"))

	sess, err := NewSession(key)
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}

	if sess == nil {
		t.Error("session is nil")
	}
}

func TestReadWriteFrame(t *testing.T) {
	var key [32]byte
	copy(key[:], []byte("test-key-123456789012345678901"))

	sess, _ := NewSession(key)

	var buf bytes.Buffer
	payload := []byte("hello world")

	// Write a frame
	err := sess.WriteFrame(&buf, FrameTypeData, payload)
	if err != nil {
		t.Fatalf("WriteFrame failed: %v", err)
	}

	// Reset session for reading
	sess.ResetNonce()

	// Read the frame
	frame, err := sess.ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}

	if frame.Type != FrameTypeData {
		t.Errorf("frame type mismatch: got %v, want %v", frame.Type, FrameTypeData)
	}

	if !bytes.Equal(frame.Payload, payload) {
		t.Errorf("payload mismatch: got %v, want %v", frame.Payload, payload)
	}
}

func TestMultipleFrames(t *testing.T) {
	var key [32]byte
	copy(key[:], []byte("test-key-123456789012345678901"))

	sess, _ := NewSession(key)

	var buf bytes.Buffer

	payloads := [][]byte{
		[]byte("frame 1"),
		[]byte("frame 2"),
		[]byte("frame 3"),
	}

	// Write frames
	for _, payload := range payloads {
		err := sess.WriteFrame(&buf, FrameTypeData, payload)
		if err != nil {
			t.Fatalf("WriteFrame failed: %v", err)
		}
	}

	// Reset for reading
	sess.ResetNonce()

	// Read frames
	for i, expectedPayload := range payloads {
		frame, err := sess.ReadFrame(&buf)
		if err != nil {
			t.Fatalf("ReadFrame %d failed: %v", i, err)
		}

		if !bytes.Equal(frame.Payload, expectedPayload) {
			t.Errorf("frame %d payload mismatch: got %v, want %v", i, frame.Payload, expectedPayload)
		}
	}
}
