package inbound

import (
	"bytes"
	"crypto/rand"
	"net"
	"testing"
)

func TestEncryption(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	sender, err := NewSession(key)
	if err != nil {
		t.Fatal(err)
	}

	receiver, err := NewSession(key)
	if err != nil {
		t.Fatal(err)
	}

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	original := []byte("test data")

	// sender encrypts and writes
	go func() {
		_ = sender.WriteFrame(c1, FrameTypeData, original)
	}()

	// receiver reads and decrypts
	frame, err := receiver.ReadFrame(c2)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(original, frame.Payload) {
		t.Fatal("encryption/decryption failed")
	}
}