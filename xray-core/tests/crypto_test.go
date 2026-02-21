package reflex_test

import (
	"bytes"
	"testing"

	"github.com/xtls/xray-core/proxy/reflex"
)

func TestKeyPair(t *testing.T) {
	priv, pub, err := reflex.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if priv == [32]byte{} || pub == [32]byte{} {
		t.Fatal("generated zero keys")
	}
}

func TestSharedKey(t *testing.T) {
	priv1, pub1, _ := reflex.GenerateKeyPair()
	priv2, pub2, _ := reflex.GenerateKeyPair()

	shared1 := reflex.DeriveSharedKey(priv1, pub2)
	shared2 := reflex.DeriveSharedKey(priv2, pub1)

	if !bytes.Equal(shared1[:], shared2[:]) {
		t.Fatal("shared keys do not match")
	}
}

func TestSessionKey(t *testing.T) {
	sharedKey := [32]byte{1, 2, 3}
	salt := []byte("salt")
	c2s_1, s2c_1 := reflex.DeriveSessionKeys(sharedKey, salt)
	c2s_2, s2c_2 := reflex.DeriveSessionKeys(sharedKey, salt)

	if !bytes.Equal(c2s_1, c2s_2) || !bytes.Equal(s2c_1, s2c_2) {
		t.Fatal("session keys do not match")
	}

	if bytes.Equal(c2s_1, s2c_1) {
		t.Fatal("c2s and s2c keys should be different")
	}

	c2s_3, _ := reflex.DeriveSessionKeys(sharedKey, []byte("other"))
	if bytes.Equal(c2s_1, c2s_3) {
		t.Fatal("session keys should be different for different salts")
	}
}

func TestConstants(t *testing.T) {
	if reflex.ReflexMagic != 0x52454658 {
		t.Error("invalid ReflexMagic")
	}
}
