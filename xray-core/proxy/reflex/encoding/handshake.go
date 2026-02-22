package encoding

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"time"

	"golang.org/x/crypto/curve25519"
)

// ClientHandshake represents the initial handshake packet from client
type ClientHandshake struct {
	PublicKey [32]byte // X25519 public key
	UserID    [16]byte // UUID in binary form
	Timestamp int64    // Unix timestamp
	Nonce     [16]byte // Random nonce for replay prevention
	Padding   []byte   // Variable length padding
}

// ServerHandshake represents the response handshake from server
type ServerHandshake struct {
	PublicKey [32]byte // X25519 public key
	Padding   []byte   // Variable length padding
}

// ClientHandshakePacket is the complete client handshake packet with magic
type ClientHandshakePacket struct {
	Magic     [4]byte
	Handshake ClientHandshake
}

// KeyPair represents a public/private key pair
type KeyPair struct {
	PrivateKey [32]byte
	PublicKey  [32]byte
}

// GenerateKeyPair generates a new X25519 key pair
func GenerateKeyPair() (*KeyPair, error) {
	var privateKey [32]byte
	if _, err := io.ReadFull(rand.Reader, privateKey[:]); err != nil {
		return nil, errors.New("failed to generate private key")
	}

	// X25519 requires clamping the private key
	privateKey[0] &= 248
	privateKey[31] = (privateKey[31] & 127) | 64

	var publicKey [32]byte
	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}, nil
}

// DeriveSharedSecret derives a shared secret using X25519
func DeriveSharedSecret(privateKey, peerPublicKey [32]byte) ([32]byte, error) {
	out, err := curve25519.X25519(privateKey[:], peerPublicKey[:])
	if err != nil {
		return [32]byte{}, err
	}
	var secret [32]byte
	copy(secret[:], out)
	return secret, nil
}

// NewClientHandshake creates a new client handshake packet
func NewClientHandshake(userID [16]byte, publicKey [32]byte) *ClientHandshake {
	hs := &ClientHandshake{
		PublicKey: publicKey,
		UserID:    userID,
		Timestamp: time.Now().Unix(),
	}

	// Generate random nonce
	if _, err := io.ReadFull(rand.Reader, hs.Nonce[:]); err != nil {
		copy(hs.Nonce[:], []byte("reflex-default-nc"))
	}

	// Add some padding (variable length for obfuscation)
	paddingLen := 32 + cryptoRandInt(32)
	hs.Padding = make([]byte, paddingLen)
	if _, err := io.ReadFull(rand.Reader, hs.Padding); err != nil {
		for i := range hs.Padding {
			hs.Padding[i] = 0
		}
	}

	return hs
}

// NewServerHandshake creates a new server handshake packet
func NewServerHandshake(publicKey [32]byte) *ServerHandshake {
	hs := &ServerHandshake{
		PublicKey: publicKey,
	}

	// Add some padding
	paddingLen := 16 + cryptoRandInt(16)
	hs.Padding = make([]byte, paddingLen)
	if _, err := io.ReadFull(rand.Reader, hs.Padding); err != nil {
		for i := range hs.Padding {
			hs.Padding[i] = 0
		}
	}

	return hs
}

// MarshalClientHandshake marshals the client handshake to bytes
func MarshalClientHandshake(hs *ClientHandshake) []byte {
	buf := make([]byte, 32+16+8+16+len(hs.Padding))
	off := 0

	copy(buf[off:], hs.PublicKey[:])
	off += 32

	copy(buf[off:], hs.UserID[:])
	off += 16

	binary.BigEndian.PutUint64(buf[off:], uint64(hs.Timestamp))
	off += 8

	copy(buf[off:], hs.Nonce[:])
	off += 16

	copy(buf[off:], hs.Padding)

	return buf
}

// UnmarshalClientHandshake unmarshals the client handshake from bytes
func UnmarshalClientHandshake(data []byte) (*ClientHandshake, error) {
	if len(data) < 72 {
		return nil, errors.New("handshake data too short")
	}

	hs := &ClientHandshake{}
	off := 0

	copy(hs.PublicKey[:], data[off:off+32])
	off += 32

	copy(hs.UserID[:], data[off:off+16])
	off += 16

	hs.Timestamp = int64(binary.BigEndian.Uint64(data[off : off+8]))
	off += 8

	copy(hs.Nonce[:], data[off:off+16])
	off += 16

	if len(data) > off {
		hs.Padding = make([]byte, len(data)-off)
		copy(hs.Padding, data[off:])
	}

	return hs, nil
}

// MarshalServerHandshake marshals the server handshake to bytes
func MarshalServerHandshake(hs *ServerHandshake) []byte {
	buf := make([]byte, 32+len(hs.Padding))
	copy(buf, hs.PublicKey[:])
	copy(buf[32:], hs.Padding)
	return buf
}

// UnmarshalServerHandshake unmarshals the server handshake from bytes
func UnmarshalServerHandshake(data []byte) (*ServerHandshake, error) {
	if len(data) < 32 {
		return nil, errors.New("handshake data too short")
	}

	hs := &ServerHandshake{}
	copy(hs.PublicKey[:], data[:32])

	if len(data) > 32 {
		hs.Padding = make([]byte, len(data)-32)
		copy(hs.Padding, data[32:])
	}

	return hs, nil
}

func cryptoRandInt(maxExclusive int) int {
	if maxExclusive <= 0 {
		return 0
	}
	var b [1]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		return 0
	}
	return int(b[0]) % maxExclusive
}
