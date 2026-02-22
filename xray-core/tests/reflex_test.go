package tests

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/xtls/xray-core/proxy/reflex"
)

func TestTrafficMorphing(t *testing.T) {
	key := make([]byte, 32)
	aead, _ := reflex.NewCipher(key)
	nonce := make([]byte, aead.NonceSize())

	originalData := []byte("hello aparat simulation")

	targetSize := 500
	paddedPayload := make([]byte, targetSize)
	binary.BigEndian.PutUint16(paddedPayload[:2], uint16(len(originalData)))
	copy(paddedPayload[2:], originalData)

	encrypted := aead.Seal(nil, nonce, paddedPayload, nil)

	decrypted, err := aead.Open(nil, nonce, encrypted, nil)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if len(decrypted) < 2 {
		t.Fatal("Decrypted frame too short")
	}
	realLen := binary.BigEndian.Uint16(decrypted[:2])
	extractedData := decrypted[2 : 2+realLen]

	if !bytes.Equal(originalData, extractedData) {
		t.Errorf("Data mismatch! Expected %s, got %s", originalData, extractedData)
	}
}
