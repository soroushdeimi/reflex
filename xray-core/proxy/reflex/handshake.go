package reflex

import (
	"crypto/rand"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const ReflexMagic = 0x5246584C

type ClientHandshake struct {
	PublicKey [32]byte
	UserID    [16]byte
	PolicyReq []byte
	Timestamp int64
	Nonce     [16]byte
}

type ServerHandshake struct {
	PublicKey   [32]byte
	PolicyGrant []byte
}

type ClientHandshakePacket struct {
	Magic     [4]byte
	Handshake ClientHandshake
}

func GenerateKeyPair() (privateKey [32]byte, publicKey [32]byte, err error) {
	if _, err := io.ReadFull(rand.Reader, privateKey[:]); err != nil {
		return privateKey, publicKey, err
	}

	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	curve25519.ScalarBaseMult(&publicKey, &privateKey)
	return privateKey, publicKey, nil
}

func DeriveSharedKey(privateKey, peerPublicKey [32]byte) [32]byte {
	var shared [32]byte
	curve25519.ScalarMult(&shared, &privateKey, &peerPublicKey)
	return shared
}

func DeriveSessionKey(sharedKey [32]byte, salt []byte) []byte {
	h := hkdf.New(sha256.New, sharedKey[:], salt, []byte("reflex-session"))
	sessionKey := make([]byte, 32)
	io.ReadFull(h, sessionKey)
	return sessionKey
}
