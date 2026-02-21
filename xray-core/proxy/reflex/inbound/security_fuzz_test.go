package inbound

import (
	"bytes"
	"testing"
)

// PublicKey [32]byte -> inbound.go
// UserID [16]byte -> inbound.go
// Timestamp (8 bytes) -> inbound.go
// Nonce [16]byte -> inbound.go
// policyLen (2 bytes) -> inbound.go
// 32 + 16 + 8 + 16 + 2 = 74

func FuzzParseClientHandshakeBytes(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 74))
	// 128 * A
	f.Add(bytes.Repeat([]byte{0x41}, 128))

	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = ParseClientHandshakeBytes(raw)
	})
}

func FuzzParseDestinationAndPayload(f *testing.F) {
	// test with empty data, too short data, and valid data with payload
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 0})
	// port 0*256 + 80 = 80
	f.Add([]byte{3, 'a', 'b', 'c', 0, 80, 'x'})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = ParseDestinationAndPayload(data)
	})
}
