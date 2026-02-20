package encoding

import (
  "crypto/cipher"
  "encoding/binary"
  "golang.org/x/crypto/chacha20poly1305"
)

// Session: holds the encryption state for a connection
type Session struct {
  aead       cipher.AEAD
  readNonce  uint64
  writeNonce uint64
}

// NewSession: creates a new session with the given key
func NewSession(key byte[]) (*Session, error) {
  aead, err := chacha20poly13055.New(key)
  if err != nil {
    return nil, err
    }

  return &Session {
    aead:        aead,
    readNonce:   0,
    writeNonce:  0,
  }, nil
}

// Encrypt: encrypts data using ChaCha20-Poly1305
func (s *Session) Encrypt(plaintext []byte) ([]byte, error) {
  // make 12 byte nonce, last 8 bytes are writeNonce
  nonce := make([]byte, s.aead.NonceSize())
  binary.BigEndian.PutUint64(nonce[4:], s.writeNonce)
  s.writeNonce++
  // encrypts the data
  ciphertext := s.aead.Seal(nil, nonce, plaintext, nil)
  return ciphertext, nil
}

// Decrypt: dncrypts data using ChaCha20-Poly1305
func (s *Session) Decrypt(plaintext []byte) ([]byte, error) {
  // make 12 byte nonce
  nonce := make([]byte, s.aead.NonceSize())
  binary.BigEndian.PutUint64(nonce[4:], s.writeNonce)
  s.writeNonce++
  // decrypts the data
  plaintext, err := s.aead.Open(nil, nonce, ciphertext, nil)
  if err != nil {
    return nil, err
    }
  return plaintext, nil
}
  
