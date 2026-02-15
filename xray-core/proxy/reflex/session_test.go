package reflex

import (
	"bytes"
	"testing"
)

func TestSessionReadWriteFrame(t *testing.T) {
	key := make([]byte, 32)
	for i := 0; i < 32; i++ {
		key[i] = byte(i)
	}

	cli, err := NewSession(key)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := NewSession(key)
	if err != nil {
		t.Fatal(err)
	}

	var wire bytes.Buffer
	wantType := uint8(FrameTypeData)
	wantPayload := []byte("hello-reflex")

	if err := cli.WriteFrame(&wire, wantType, wantPayload); err != nil {
		t.Fatal(err)
	}

	b := wire.Bytes()
	if len(b) < 3 {
		t.Fatalf("wire too short: %d", len(b))
	}
	if b[2] != wantType {
		t.Fatalf("type mismatch in header: got %d want %d", b[2], wantType)
	}

	f, err := srv.ReadFrame(&wire)
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != wantType {
		t.Fatalf("type mismatch: got %d want %d", f.Type, wantType)
	}
	if string(f.Payload) != string(wantPayload) {
		t.Fatalf("payload mismatch: got %q want %q", f.Payload, wantPayload)
	}
}

func TestSessionNonceProgresses(t *testing.T) {
	key := make([]byte, 32)
	for i := 0; i < 32; i++ {
		key[i] = byte(100 + i)
	}

	sender, err := NewSession(key)
	if err != nil {
		t.Fatal(err)
	}

	receiver, err := NewSession(key)
	if err != nil {
		t.Fatal(err)
	}

	var wire bytes.Buffer

	if err := sender.WriteFrame(&wire, FrameTypeData, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := sender.WriteFrame(&wire, FrameTypeData, []byte("two")); err != nil {
		t.Fatal(err)
	}

	f1, err := receiver.ReadFrame(&wire)
	if err != nil {
		t.Fatal(err)
	}
	f2, err := receiver.ReadFrame(&wire)
	if err != nil {
		t.Fatal(err)
	}

	if string(f1.Payload) != "one" {
		t.Fatalf("expected 'one', got %q", f1.Payload)
	}
	if string(f2.Payload) != "two" {
		t.Fatalf("expected 'two', got %q", f2.Payload)
	}
}
