package reflex

import (
	"crypto/cipher"

	"golang.org/x/crypto/chacha20poly1305"
)

type Session struct {
	key        []byte
	aead       cipher.AEAD
	readNonce  uint64
	writeNonce uint64
}

func NewSession(sessionKey []byte) (*Session, error) {
	aead, err := chacha20poly1305.New(sessionKey)
	if err != nil {
		return nil, err
	}

	return &Session{
		key:        sessionKey,
		aead:       aead,
		readNonce:  0,
		writeNonce: 0,
	}, nil
}
