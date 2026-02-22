package reflex

import (
	"crypto/rand"
	"errors"
)

var policyAAD = []byte("reflex-policy")

// EncryptPolicy encrypts a policy blob using a UUID-derived PSK.
// The output format is: nonce(12) || ciphertext+tag.
func EncryptPolicy(psk [32]byte, plaintext []byte) ([]byte, error) {
	aead, err := NewChaCha20Poly1305(psk[:])
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := aead.Seal(nil, nonce, plaintext, policyAAD)
	out := make([]byte, 0, len(nonce)+len(ct))
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// DecryptPolicy decrypts a policy blob using a UUID-derived PSK.
func DecryptPolicy(psk [32]byte, ciphertext []byte) ([]byte, error) {
	aead, err := NewChaCha20Poly1305(psk[:])
	if err != nil {
		return nil, err
	}
	ns := aead.NonceSize()
	if len(ciphertext) < ns+aead.Overhead() {
		return nil, errors.New("reflex: policy ciphertext too short")
	}
	nonce := ciphertext[:ns]
	ct := ciphertext[ns:]
	pt, err := aead.Open(nil, nonce, ct, policyAAD)
	if err != nil {
		return nil, err
	}
	return pt, nil
}
