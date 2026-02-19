package inbound

import (
	"bufio"
	"bytes"
	"testing"
)

// FuzzHandshake sends random data to the handshake processor to find crashes
func FuzzHandshake(f *testing.F) {
	handler := &Handler{} // Dummy handler

	f.Add([]byte{0x52, 0x46, 0x58, 0x4C, 0x01, 0x02}) // Seed data
	f.Fuzz(func(t *testing.T, data []byte) {
		reader := bufio.NewReader(bytes.NewReader(data))
		// We ignore errors because we are only looking for PANICS (crashes)
		_, _ = handler.ProcessHandshake(nil, reader)
	})
}
