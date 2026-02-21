package reflex

import (
    "bytes"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "io"
    "testing"
)

func TestReflexEncryption(t *testing.T) {
    // 1. تولید کلید 32 بایتی (AES-256)
    key := make([]byte, 32)
    if _, err := io.ReadFull(rand.Reader, key); err != nil {
        t.Fatal(err)
    }

    plaintext := []byte("secret_data_for_reflex_protocol")

    // 2. فرآیند رمزگذاری
    block, _ := aes.NewCipher(key)
    gcm, _ := cipher.NewGCM(block)
    nonce := make([]byte, gcm.NonceSize())
    io.ReadFull(rand.Reader, nonce)

    ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

    // 3. فرآیند رمزگشایی
    nonceSize := gcm.NonceSize()
    if len(ciphertext) < nonceSize {
        t.Fatal("ciphertext too short")
    }
    extractedNonce, actualCiphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
    decrypted, err := gcm.Open(nil, extractedNonce, actualCiphertext, nil)

    if err != nil {
        t.Fatalf("Decryption error: %v", err)
    }

    // 4. مقایسه نهایی
    if !bytes.Equal(plaintext, decrypted) {
        t.Error("Data mismatch: Plaintext and Decrypted data are not same")
    } else {
        t.Log("Encryption & Decryption: SUCCESSFUL (AES-GCM)")
    }
}