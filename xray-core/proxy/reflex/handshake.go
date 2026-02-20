package reflex

import (
	"crypto/sha256"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// ClientHandshake represents the client's initial handshake data
type ClientHandshake struct {
	PublicKey [32]byte // X25519 public key
	UserID    [16]byte // User UUID (16 bytes)
	PolicyReq []byte   // Policy request (encrypted with pre-shared key)
	Timestamp int64    // Unix timestamp
	Nonce     [16]byte // Nonce to prevent replay attacks
}

// ServerHandshake represents the server's handshake response
type ServerHandshake struct {
	PublicKey   [32]byte // Server's X25519 public key
	PolicyGrant []byte   // Policy grant (encrypted)
}

// DeriveSharedKey performs X25519 key exchange
func DeriveSharedKey(privateKey, peerPublicKey *[32]byte) [32]byte {
	var shared [32]byte
	curve25519.ScalarMult(&shared, privateKey, peerPublicKey)
	return shared
}

// DeriveSessionKey derives session key from shared key using HKDF
func DeriveSessionKey(sharedKey [32]byte, salt []byte) []byte {
	reader := hkdf.New(sha256.New, sharedKey[:], salt, []byte("reflex-session-v1"))
	sessionKey := make([]byte, 32)
	if _, err := io.ReadFull(reader, sessionKey); err != nil {
		panic(err) // Should never happen with proper HKDF
	}
	return sessionKey
}

// GenerateKeyPair generates a new X25519 key pair
func GenerateKeyPair() (*[32]byte, *[32]byte, error) {
	var privateKey, publicKey [32]byte
	
	// Generate random private key
	if _, err := io.ReadFull(io.Reader(nil), privateKey[:]); err != nil {
		// Use crypto/rand instead
		return nil, nil, err
	}
	
	// Derive public key
	curve25519.ScalarBaseMult(&publicKey, &privateKey)
	
	return &privateKey, &publicKey, nil
}

// WriteHandshake writes a handshake to the writer
func (h *ClientHandshake) Write(w io.Writer) error {
	// Write magic number
	magic := make([]byte, 4)
	binary.BigEndian.PutUint32(magic, ReflexMagic)
	if _, err := w.Write(magic); err != nil {
		return err
	}
	
	// Write public key
	if _, err := w.Write(h.PublicKey[:]); err != nil {
		return err
	}
	
	// Write user ID
	if _, err := w.Write(h.UserID[:]); err != nil {
		return err
	}
	
	// Write timestamp
	timestampBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBuf, uint64(h.Timestamp))
	if _, err := w.Write(timestampBuf); err != nil {
		return err
	}
	
	// Write nonce
	if _, err := w.Write(h.Nonce[:]); err != nil {
		return err
	}
	
	// Write policy request length and data
	policyLenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(policyLenBuf, uint16(len(h.PolicyReq)))
	if _, err := w.Write(policyLenBuf); err != nil {
		return err
	}
	if len(h.PolicyReq) > 0 {
		if _, err := w.Write(h.PolicyReq); err != nil {
			return err
		}
	}
	
	return nil
}

// ReadClientHandshake reads a client handshake from the reader
func ReadClientHandshake(r io.Reader) (*ClientHandshake, error) {
	h := &ClientHandshake{}
	
	// Read magic number
	magic := make([]byte, 4)
	if _, err := io.ReadFull(r, magic); err != nil {
		return nil, err
	}
	
	// Read public key
	if _, err := io.ReadFull(r, h.PublicKey[:]); err != nil {
		return nil, err
	}
	
	// Read user ID
	if _, err := io.ReadFull(r, h.UserID[:]); err != nil {
		return nil, err
	}
	
	// Read timestamp
	timestampBuf := make([]byte, 8)
	if _, err := io.ReadFull(r, timestampBuf); err != nil {
		return nil, err
	}
	h.Timestamp = int64(binary.BigEndian.Uint64(timestampBuf))
	
	// Read nonce
	if _, err := io.ReadFull(r, h.Nonce[:]); err != nil {
		return nil, err
	}
	
	// Read policy request
	policyLenBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, policyLenBuf); err != nil {
		return nil, err
	}
	policyLen := binary.BigEndian.Uint16(policyLenBuf)
	if policyLen > 0 {
		h.PolicyReq = make([]byte, policyLen)
		if _, err := io.ReadFull(r, h.PolicyReq); err != nil {
			return nil, err
		}
	}
	
	return h, nil
}

// WriteServerHandshake writes a server handshake to the writer
func (h *ServerHandshake) Write(w io.Writer) error {
	// Write public key
	if _, err := w.Write(h.PublicKey[:]); err != nil {
		return err
	}
	
	// Write policy grant length and data
	grantLenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(grantLenBuf, uint16(len(h.PolicyGrant)))
	if _, err := w.Write(grantLenBuf); err != nil {
		return err
	}
	if len(h.PolicyGrant) > 0 {
		if _, err := w.Write(h.PolicyGrant); err != nil {
			return err
		}
	}
	
	return nil
}

// ReadServerHandshake reads a server handshake from the reader
func ReadServerHandshake(r io.Reader) (*ServerHandshake, error) {
	h := &ServerHandshake{}
	
	// Read public key
	if _, err := io.ReadFull(r, h.PublicKey[:]); err != nil {
		return nil, err
	}
	
	// Read policy grant
	grantLenBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, grantLenBuf); err != nil {
		return nil, err
	}
	grantLen := binary.BigEndian.Uint16(grantLenBuf)
	if grantLen > 0 {
		h.PolicyGrant = make([]byte, grantLen)
		if _, err := io.ReadFull(r, h.PolicyGrant); err != nil {
			return nil, err
		}
	}
	
	return h, nil
}
