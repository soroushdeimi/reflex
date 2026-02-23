package inbound

import (
	"bytes"
	"testing"
)

func FuzzParseDestination(f *testing.F) {
	f.Add([]byte{0x01, 127, 0, 0, 1, 0, 80})
	f.Add([]byte{0x03, 3, 'a', 'b', 'c', 0, 80})
	f.Add([]byte{0xFF, 0, 0, 0})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseDestination(data)
	})
}

func FuzzSessionReadFrame(f *testing.F) {
	f.Add([]byte{0x00, 0x00, FrameTypeData})
	f.Add([]byte{0x00, 0x01, 0xFF, 0x00})
	f.Add([]byte{})

	key := bytes.Repeat([]byte{0x22}, 32)
	f.Fuzz(func(t *testing.T, data []byte) {
		sess, err := NewSession(key)
		if err != nil {
			t.Fatalf("failed to create session: %v", err)
		}
		_, _ = sess.ReadFrame(bytes.NewReader(data))
	})
}

