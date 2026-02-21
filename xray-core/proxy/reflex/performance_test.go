package reflex

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "fmt"
    "io"
    "testing"
)

// شبیه‌ساز بخش رمزنگاری برای تست سرعت
type MockSession struct {
    gcm cipher.AEAD
}

func NewMockSession() *MockSession {
    key := make([]byte, 32)
    io.ReadFull(rand.Reader, key)
    block, _ := aes.NewCipher(key)
    gcm, _ := cipher.NewGCM(block)
    return &MockSession{gcm: gcm}
}

func (s *MockSession) encrypt(data []byte) []byte {
    nonce := make([]byte, s.gcm.NonceSize())
    return s.gcm.Seal(nonce, nonce, data, nil)
}

// ۱. تست پایه سرعت
func BenchmarkEncryption(b *testing.B) {
    session := NewMockSession()
    data := make([]byte, 1024)
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        session.encrypt(data)
    }
}

// ۲. تست با اندازه‌های مختلف پکت (از ۶۴ بایت تا ۱۶ کیلوبایت)
func BenchmarkEncryptionSizes(b *testing.B) {
    sizes := []int{64, 256, 1024, 4096, 16384}
    for _, size := range sizes {
        b.Run(fmt.Sprintf("Size-%d", size), func(b *testing.B) {
            session := NewMockSession()
            data := make([]byte, size)
            b.ResetTimer()
            for i := 0; i < b.N; i++ {
                session.encrypt(data)
            }
        })
    }
}

// ۳. تست تخصیص حافظه (Memory Allocation)
func BenchmarkMemoryAllocation(b *testing.B) {
    session := NewMockSession()
    data := make([]byte, 1024)
    b.ReportAllocs()
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        session.encrypt(data)
    }
}