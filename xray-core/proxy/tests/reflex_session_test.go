package tests

import (
	"bytes"
	"testing"

	"github.com/xtls/xray-core/proxy/reflex"
)

func TestReflexSessionEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	sess, err := reflex.NewSession(key)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	payload := []byte("hello world")
	if err := sess.WriteFrame(&buf, reflex.FrameTypeData, payload); err != nil {
		t.Fatal(err)
	}

	frame, err := sess.ReadFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if frame.Type != reflex.FrameTypeData {
		t.Fatalf("expected type Data, got %d", frame.Type)
	}
	if !bytes.Equal(frame.Payload, payload) {
		t.Fatalf("payload mismatch: got %q", frame.Payload)
	}
}

func TestReflexSessionReplayRejected(t *testing.T) {
	key := make([]byte, 32)
	sess, err := reflex.NewSession(key)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	_ = sess.WriteFrame(&buf, reflex.FrameTypeData, []byte("once"))
	b := buf.Bytes()

	// First read: must succeed
	r := bytes.NewReader(b)
	frame, err := sess.ReadFrame(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(frame.Payload) != "once" {
		t.Fatalf("first read payload: got %q", frame.Payload)
	}

	// Replay same bytes: must be rejected
	r2 := bytes.NewReader(b)
	_, err = sess.ReadFrame(r2)
	if err == nil {
		t.Fatal("replay should be rejected")
	}
	if err.Error() != "reflex: replay detected" {
		t.Fatalf("expected replay error, got: %v", err)
	}
}
