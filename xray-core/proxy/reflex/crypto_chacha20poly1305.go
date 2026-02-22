package reflex

import (
	"crypto/cipher"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

func NewChaCha20Poly1305(key []byte) (cipher.AEAD, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, errors.New("invalid key length")
	}
	return chacha20poly1305.New(key)
}
