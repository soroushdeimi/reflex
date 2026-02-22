package reflex

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash"
)

// hkdfExtract is HKDF-Extract(salt, IKM) = HMAC-Hash(salt, IKM).
func hkdfExtract(hashFunc func() hash.Hash, salt, ikm []byte) []byte {
	if salt == nil {
		salt = make([]byte, hashFunc().Size())
	}
	h := hmac.New(hashFunc, salt)
	_, _ = h.Write(ikm)
	return h.Sum(nil)
}

// hkdfExpand is HKDF-Expand(PRK, info, L).
func hkdfExpand(hashFunc func() hash.Hash, prk, info []byte, length int) []byte {
	hLen := hashFunc().Size()
	if length <= 0 {
		return nil
	}
	n := (length + hLen - 1) / hLen
	var (
		t   []byte
		okm []byte
	)
	for i := 1; i <= n; i++ {
		h := hmac.New(hashFunc, prk)
		_, _ = h.Write(t)
		_, _ = h.Write(info)
		_, _ = h.Write([]byte{byte(i)})
		t = h.Sum(nil)
		okm = append(okm, t...)
	}
	return okm[:length]
}

// HKDFSHA256 derives key material using HKDF-SHA256.
func HKDFSHA256(ikm, salt, info []byte, length int) []byte {
	prk := hkdfExtract(sha256.New, salt, ikm)
	return hkdfExpand(sha256.New, prk, info, length)
}

// DerivePSK derives a pre-shared key from a user UUID.
//
// Spec note: the assignment suggests using UUID-derived key material.
func DerivePSK(userID [16]byte) [32]byte {
	return sha256.Sum256(userID[:])
}
