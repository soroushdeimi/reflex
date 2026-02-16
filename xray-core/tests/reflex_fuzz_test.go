package tests

import (
	"bytes"
	"testing"

	"github.com/xtls/xray-core/proxy/reflex/inbound"
)

func FuzzParseClientHandshakeBytes(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 74))
	f.Add(bytes.Repeat([]byte{0x41}, 128))

	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = inbound.ParseClientHandshakeBytes(raw)
	})
}

func FuzzParseDestinationAndPayload(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte{3, 'a', 'b', 'c', 0, 80, 'x'})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = inbound.ParseDestinationAndPayload(data)
	})
}
