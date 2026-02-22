package reflex

import (
	"bytes"
	"testing"
)

func TestEncryptDecryptPolicy_RoundTrip(t *testing.T) {
	u, err := ParseUUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
	if err != nil {
		t.Fatal(err)
	}
	psk := DerivePSK(u)

	plaintext := []byte("hello reflex policy")

	ct, err := EncryptPolicy(psk, plaintext)
	if err != nil {
		t.Fatalf("EncryptPolicy err: %v", err)
	}
	if len(ct) == 0 {
		t.Fatalf("ciphertext empty")
	}
	if bytes.Equal(ct, plaintext) {
		t.Fatalf("ciphertext must differ from plaintext")
	}

	got, err := DecryptPolicy(psk, ct)
	if err != nil {
		t.Fatalf("DecryptPolicy err: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round-trip mismatch: got=%q want=%q", got, plaintext)
	}
}

func TestDecryptPolicy_TamperShouldFail(t *testing.T) {
	u, err := ParseUUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
	if err != nil {
		t.Fatal(err)
	}
	psk := DerivePSK(u)

	plaintext := []byte("tamper test")
	ct, err := EncryptPolicy(psk, plaintext)
	if err != nil {
		t.Fatalf("EncryptPolicy err: %v", err)
	}

	// tamper one byte
	ct[len(ct)/2] ^= 0xFF

	_, err = DecryptPolicy(psk, ct)
	if err == nil {
		t.Fatalf("expected decrypt to fail after tampering")
	}
}
