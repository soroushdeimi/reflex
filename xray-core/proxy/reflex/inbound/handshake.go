package inbound

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
)

// ReflexMagic is the 4-byte magic number for quick protocol detection ("REFX").
const ReflexMagic = 0x5246584C

// MinHandshakeSize is the minimum bytes to peek for protocol detection.
// magic(4) + pubkey(32) + userid(16) + timestamp(8) + nonce(16) = 76 bytes.
const MinHandshakeSize = 76

// ClientHandshake is the client's first packet (key exchange + auth).
type ClientHandshake struct {
	PublicKey [32]byte
	UserID    [16]byte
	PolicyReq []byte
	Timestamp int64
	Nonce     [16]byte
}

// ServerHandshake is the server's response.
type ServerHandshake struct {
	PublicKey   [32]byte
	PolicyGrant []byte
}

// generateKeyPair generates a X25519 key pair.
func generateKeyPair() (privateKey, publicKey [32]byte, err error) {
	if _, err := rand.Read(privateKey[:]); err != nil {
		return privateKey, publicKey, err
	}
	curve25519.ScalarBaseMult(&publicKey, &privateKey)
	return privateKey, publicKey, nil
}

// deriveSharedKey computes the X25519 shared secret.
func deriveSharedKey(privateKey, peerPublicKey [32]byte) [32]byte {
	var shared [32]byte
	curve25519.ScalarMult(&shared, &privateKey, &peerPublicKey)
	return shared
}

// deriveSessionKey derives a 32-byte session key from the shared secret using HKDF.
func deriveSessionKey(sharedKey [32]byte, salt []byte) []byte {
	hk := hkdf.New(sha256.New, sharedKey[:], salt, []byte("reflex-session"))
	sessionKey := make([]byte, 32)
	_, _ = io.ReadFull(hk, sessionKey)
	return sessionKey
}

// readClientHandshakeMagic reads the magic-number format: magic(4) + pubkey(32) + userid(16) + timestamp(8) + nonce(16).
func readClientHandshakeMagic(r io.Reader) (*ClientHandshake, error) {
	var magic [4]byte
	if _, err := io.ReadFull(r, magic[:]); err != nil {
		return nil, err
	}
	if binary.BigEndian.Uint32(magic[:]) != ReflexMagic {
		return nil, errNotReflex
	}
	hs := &ClientHandshake{}
	if _, err := io.ReadFull(r, hs.PublicKey[:]); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(r, hs.UserID[:]); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.BigEndian, &hs.Timestamp); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(r, hs.Nonce[:]); err != nil {
		return nil, err
	}
	return hs, nil
}

// writeServerHandshakeMagic writes the server response: magic(4) + pubkey(32) + policy_grant_len(2) + policy_grant.
func writeServerHandshakeMagic(w io.Writer, sh *ServerHandshake) error {
	if _, err := w.Write([]byte{
		byte(ReflexMagic >> 24), byte((ReflexMagic >> 16) & 0xFF), byte((ReflexMagic >> 8) & 0xFF), byte(ReflexMagic & 0xFF),
	}); err != nil {
		return err
	}
	if _, err := w.Write(sh.PublicKey[:]); err != nil {
		return err
	}
	plen := len(sh.PolicyGrant)
	if plen > 0xffff {
		plen = 0xffff
	}
	if err := binary.Write(w, binary.BigEndian, uint16(plen)); err != nil {
		return err
	}
	if plen > 0 {
		if _, err := w.Write(sh.PolicyGrant[:plen]); err != nil {
			return err
		}
	}
	return nil
}

// authenticateUser finds a user by UUID (16 bytes). Returns nil if not found.
func (h *Handler) authenticateUser(userID [16]byte) *protocol.MemoryUser {
	u, err := uuid.ParseBytes(userID[:])
	if err != nil {
		return nil
	}
	idStr := u.String()
	for _, user := range h.clients {
		if user.Account.(*MemoryAccount).Id == idStr {
			return user
		}
	}
	return nil
}

// errNotReflex is returned when the stream is not a Reflex handshake.
var errNotReflex = errors.New("not reflex protocol")
