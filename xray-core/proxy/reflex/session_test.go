package reflex

import (
	"bytes"
	"testing"
)

func TestSession_ReadWriteFrame_RoundTrip(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = byte(i)
	}
	w, err := NewSession(key)
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewSession(key)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("hello")
	buf := new(bytes.Buffer)
	if err := w.WriteFrame(buf, FrameTypeData, msg); err != nil {
		t.Fatal(err)
	}

	f, err := r.ReadFrame(buf)
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != FrameTypeData {
		t.Fatalf("unexpected type: %d", f.Type)
	}
	if !bytes.Equal(f.Payload, msg) {
		t.Fatalf("payload mismatch: got %q want %q", string(f.Payload), string(msg))
	}
}

func TestSession_ReplayedCiphertextFails(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = byte(0xA0 + i)
	}
	w, err := NewSession(key)
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewSession(key)
	if err != nil {
		t.Fatal(err)
	}

	msg := bytes.Repeat([]byte("Z"), 64)
	buf := new(bytes.Buffer)
	if err := w.WriteFrame(buf, FrameTypeData, msg); err != nil {
		t.Fatal(err)
	}
	frameBytes := append([]byte(nil), buf.Bytes()...) // copy

	// replay the exact same ciphertext twice
	combined := append(append([]byte(nil), frameBytes...), frameBytes...)
	rr := bytes.NewReader(combined)

	if _, err := r.ReadFrame(rr); err != nil {
		t.Fatalf("first read should succeed, got: %v", err)
	}
	if _, err := r.ReadFrame(rr); err == nil {
		t.Fatalf("second read should fail due to nonce mismatch/replay")
	}
}

func TestSession_TamperedFrameTypeFailsAAD(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = byte(0x10 + i)
	}
	w, err := NewSession(key)
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewSession(key)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("attack-me")
	buf := new(bytes.Buffer)
	if err := w.WriteFrame(buf, FrameTypeData, msg); err != nil {
		t.Fatal(err)
	}

	b := append([]byte(nil), buf.Bytes()...)
	if len(b) < 3 {
		t.Fatal("frame too short")
	}

	// header[2] is frameType in our framing
	b[2] = FrameTypeClose // tamper

	if _, err := r.ReadFrame(bytes.NewReader(b)); err == nil {
		t.Fatalf("expected Open() to fail due to AAD (frameType) mismatch")
	}
}
