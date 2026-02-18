package inbound

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

func TestSessionRoundtrip(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	session, err := NewSession(key)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	payload := []byte("test data")
	if err := session.WriteFrame(&buf, FrameTypeData, payload); err != nil {
		t.Fatal(err)
	}
	frame, err := session.ReadFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if frame.Type != FrameTypeData {
		t.Errorf("frame type = %d, want %d", frame.Type, FrameTypeData)
	}
	if !bytes.Equal(frame.Payload, payload) {
		t.Errorf("payload = %q, want %q", frame.Payload, payload)
	}
}

func TestSessionReplayRejected(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	session, err := NewSession(key)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	_ = session.WriteFrame(&buf, FrameTypeData, []byte("once"))
	encrypted := buf.Bytes()
	// Feed same ciphertext twice: second read must fail (AEAD reuse)
	r := bytes.NewReader(encrypted)
	_, err = session.ReadFrame(r)
	if err != nil {
		t.Fatal(err)
	}
	_, err = session.ReadFrame(r)
	if err == nil {
		t.Fatal("replay should be rejected")
	}
}

func TestSessionMultipleFrames(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	s, err := NewSession(key)
	if err != nil {
		t.Fatal(err)
	}
	var w bytes.Buffer
	payloads := [][]byte{[]byte("a"), []byte("hello"), []byte("")}
	for i, p := range payloads {
		if err := s.WriteFrame(&w, FrameTypeData, p); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	r := bytes.NewReader(w.Bytes())
	for i, want := range payloads {
		frame, err := s.ReadFrame(r)
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		if !bytes.Equal(frame.Payload, want) {
			t.Errorf("frame %d payload = %q, want %q", i, frame.Payload, want)
		}
	}
	_, err = s.ReadFrame(r)
	if err != io.EOF && err != nil {
		t.Errorf("expected EOF or short read, got %v", err)
	}
}
