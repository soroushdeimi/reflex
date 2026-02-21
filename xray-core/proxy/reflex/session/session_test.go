package session

import (
	"crypto/rand"
	"net"
	"testing"
)

func TestSessionEncryption(t *testing.T) {

	key := make([]byte, 32)
	rand.Read(key)

	s1, err := NewSession(key)
	if err != nil {
		t.Fatal(err)
	}

	s2, err := NewSession(key)
	if err != nil {
		t.Fatal(err)
	}

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	go func() {
		err := s1.WriteFrame(c1, FrameTypeData, []byte("hello"))
		if err != nil {
			t.Error(err)
		}
	}()

	frame, err := s2.ReadFrame(c2)
	if err != nil {
		t.Fatal(err)
	}

	if string(frame.Payload) != "hello" {
		t.Fatal("payload mismatch")
	}
}
