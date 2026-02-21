// Package reflex implements the Reflex proxy protocol for Xray-Core.
// این پکیج پروتکل پراکسی رفلکس را برای ایکس‌ری پیاده‌سازی می‌کند.
package reflex

import (
	"crypto/rand"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// GenerateKeyPair generates a random X25519 private/public key pair.
// یک جفت کلید عمومی و خصوصی تصادفی برای اکس۲۵۵۱۹ تولید می‌کند.
func GenerateKeyPair() ([32]byte, [32]byte, error) {
	var privateKey [32]byte
	if _, err := io.ReadFull(rand.Reader, privateKey[:]); err != nil {
		return [32]byte{}, [32]byte{}, err
	}
	var publicKey [32]byte
	curve25519.ScalarBaseMult(&publicKey, &privateKey)
	return privateKey, publicKey, nil
}

// DeriveSharedKey computes the X25519 shared secret.
// کلید مشترک را با استفاده از اکس۲۵۵۱۹ محاسبه می‌کند.
func DeriveSharedKey(privateKey, peerPublicKey [32]byte) [32]byte {
	var shared [32]byte
	curve25519.ScalarMult(&shared, &privateKey, &peerPublicKey)
	return shared
}

// DeriveSessionKeys derives unique session keys for client-to-server (C2S) and server-to-client (S2C) directions using HKDF.
// کلیدهای نشست منحصر به فرد برای جهت‌های کلاینت به سرور و سرور به کلاینت را با استفاده از اچ‌کی‌دی‌اف استخراج می‌کند.
func DeriveSessionKeys(sharedKey [32]byte, salt []byte) ([]byte, []byte) {
	c2s := make([]byte, 32)
	s2c := make([]byte, 32)

	hkC2S := hkdf.New(sha256.New, sharedKey[:], salt, []byte("reflex-c2s"))
	hkC2S.Read(c2s)

	hkS2C := hkdf.New(sha256.New, sharedKey[:], salt, []byte("reflex-s2c"))
	hkS2C.Read(s2c)

	return c2s, s2c
}

// ReflexMagic is the protocol magic number ("REFX" in Big Endian).
// شناسه جادویی پروتکل رفلکس.
const ReflexMagic = 0x52454658

// ClientHandshake represents the initial packet sent by the client.
// بسته اولیه که توسط کلاینت در شروع دست‌تکانی ارسال می‌شود.
type ClientHandshake struct {
	PublicKey [32]byte // Client's ephemeral X25519 public key.
	UserID    [16]byte // 128-bit User ID for authentication.
	Timestamp int64    // Unix timestamp to prevent replay/drift attacks.
	Nonce     [16]byte // Unique nonce for replay protection within the same timestamp.
}

// ServerHandshake represents the response packet sent by the server.
// بسته پاسخی که توسط سرور در انتهای دست‌تکانی ارسال می‌شود.
type ServerHandshake struct {
	PublicKey [32]byte // Server's ephemeral X25519 public key.
}
