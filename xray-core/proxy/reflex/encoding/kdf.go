package encoding

import (
    "crypto/sha256"
    "io"
    "golang.org/x/crypto/hkdf
  )

// derivenKeys: makes encryption key from the shared secret
func derivenKeys(sahredSecret []byte, salt []byte) ([]byte, []byte, error) {
  // setup HKDF with sha256
  hkdfReader := hkdf.New(sha256.New, sharedSecret, salt, []byte("reflex-handshake"))

  // make 32 byte key for chacha20
  key:= make([]byte, 32)
  if _, err := io.ReadFull(hkdfReader, key); err != nil {
    return nil, nil, err
  }

  //make 12 byte nonce salt
  nonceSalt := make([]byte, 32)
  if _, err := io.ReadFull(hkdfReader, nonceSalt); err != nil {
    return nil, nil, err
  }

  return key, nonceSalt, err
}
