package handshake

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
)

const (
	// AES-GCM uses 12-byte nonce.
	PolicyAEADNonceSize = 12

	// HKDF info labels (direction separation).
	policyReqInfo   = "reflex-policy-req"
	policyGrantInfo = "reflex-policy-grant"
)

type policyDirection uint8

const (
	dirReq   policyDirection = 1
	dirGrant policyDirection = 2
)

// EncryptPolicyReq encrypts a client policy request using PSK derived from UUID.
// Output format: aeadNonce(12) || ciphertext
func EncryptPolicyReq(userID [UserIDSize]byte, hsNonce [NonceSize]byte, ts int64, plaintext []byte) ([]byte, error) {
	return encryptPolicy(userID, hsNonce, ts, plaintext, dirReq, policyReqInfo, MaxPolicyReqSize)
}

// DecryptPolicyReq decrypts a client policy request.
func DecryptPolicyReq(userID [UserIDSize]byte, hsNonce [NonceSize]byte, ts int64, data []byte) ([]byte, error) {
	return decryptPolicy(userID, hsNonce, ts, data, dirReq, policyReqInfo)
}

// EncryptPolicyGrant encrypts a server policy grant.
// Output format: aeadNonce(12) || ciphertext
func EncryptPolicyGrant(userID [UserIDSize]byte, hsNonce [NonceSize]byte, ts int64, plaintext []byte) ([]byte, error) {
	return encryptPolicy(userID, hsNonce, ts, plaintext, dirGrant, policyGrantInfo, MaxPolicyGrantSize)
}

// DecryptPolicyGrant decrypts a server policy grant.
func DecryptPolicyGrant(userID [UserIDSize]byte, hsNonce [NonceSize]byte, ts int64, data []byte) ([]byte, error) {
	return decryptPolicy(userID, hsNonce, ts, data, dirGrant, policyGrantInfo)
}

func encryptPolicy(
	userID [UserIDSize]byte,
	hsNonce [NonceSize]byte,
	ts int64,
	plaintext []byte,
	dir policyDirection,
	hkdfInfo string,
	maxOut int,
) ([]byte, error) {
	// Allow empty policy.
	if len(plaintext) == 0 {
		return nil, nil
	}

	key, err := derivePolicyKey(userID, hsNonce, hkdfInfo)
	if err != nil {
		return nil, err
	}

	aead, err := newAESGCM(key)
	if err != nil {
		return nil, err
	}

	// Random AEAD nonce (12 bytes).
	var aeadNonce [PolicyAEADNonceSize]byte
	if _, err := io.ReadFull(rand.Reader, aeadNonce[:]); err != nil {
		return nil, Wrap(KindInternal, "policy: read random nonce", err)
	}

	aad := buildPolicyAAD(userID, hsNonce, ts, dir)

	ct := aead.Seal(nil, aeadNonce[:], plaintext, aad)

	outLen := PolicyAEADNonceSize + len(ct)
	if outLen > maxOut {
		return nil, New(KindInvalidHandshake, "policy: encrypted payload too large")
	}

	out := make([]byte, 0, outLen)
	out = append(out, aeadNonce[:]...)
	out = append(out, ct...)
	return out, nil
}

func decryptPolicy(
	userID [UserIDSize]byte,
	hsNonce [NonceSize]byte,
	ts int64,
	data []byte,
	dir policyDirection,
	hkdfInfo string,
) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}
	if len(data) < PolicyAEADNonceSize+16 { // 16 = GCM tag (minimum overhead)
		return nil, New(KindInvalidHandshake, "policy: ciphertext too short")
	}

	key, err := derivePolicyKey(userID, hsNonce, hkdfInfo)
	if err != nil {
		return nil, err
	}

	aead, err := newAESGCM(key)
	if err != nil {
		return nil, err
	}

	var aeadNonce [PolicyAEADNonceSize]byte
	copy(aeadNonce[:], data[:PolicyAEADNonceSize])
	ct := data[PolicyAEADNonceSize:]

	aad := buildPolicyAAD(userID, hsNonce, ts, dir)

	pt, err := aead.Open(nil, aeadNonce[:], ct, aad)
	if err != nil {
		return nil, Wrap(KindInvalidHandshake, "policy: decrypt failed", err)
	}
	return pt, nil
}

func derivePolicyKey(userID [UserIDSize]byte, hsNonce [NonceSize]byte, info string) ([32]byte, error) {
	// Base PSK = SHA256(UUID bytes)
	base := sha256.Sum256(userID[:])

	// Per-handshake key separation: HKDF(base, salt=handshake nonce, info=label)
	k, err := DeriveHKDF32(base[:], hsNonce[:], []byte(info))
	if err != nil {
		return [32]byte{}, Wrap(KindInternal, "policy: hkdf derive key", err)
	}
	return k, nil
}

func newAESGCM(key [32]byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, Wrap(KindInternal, "policy: aes new cipher", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, Wrap(KindInternal, "policy: new gcm", err)
	}
	return aead, nil
}

func buildPolicyAAD(userID [UserIDSize]byte, hsNonce [NonceSize]byte, ts int64, dir policyDirection) []byte {
	// AAD = userID(16) || ts(8 BE) || hsNonce(16) || dir(1)
	var aad [UserIDSize + 8 + NonceSize + 1]byte
	copy(aad[:UserIDSize], userID[:])

	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], uint64(ts))
	copy(aad[UserIDSize:UserIDSize+8], tsBuf[:])

	copy(aad[UserIDSize+8:UserIDSize+8+NonceSize], hsNonce[:])

	aad[len(aad)-1] = byte(dir)
	return aad[:]
}
