package tests

import (
	"bytes"
	"testing"

	"github.com/xtls/xray-core/proxy/reflex/inbound"
)

func TestSessionKeyDerivation(t *testing.T) {
	var sharedKey [32]byte
	for i := 0; i < 32; i++ {
		sharedKey[i] = 0x42
	}

	salt := []byte("test-salt")

	k1 := inbound.DeriveSessionKey(sharedKey, salt)
	k2 := inbound.DeriveSessionKey(sharedKey, salt)

	if !bytes.Equal(k1, k2) {
		t.Fatal("session key derivation is not deterministic")
	}
}
