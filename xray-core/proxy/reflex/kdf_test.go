package reflex

import (
	"bytes"
	"testing"
)

func TestHKDFSHA256_DeterministicAndLength(t *testing.T) {
	ikm := []byte("input key material")
	salt := []byte("salt")
	info := []byte("info")
	outLen := 32

	out1 := HKDFSHA256(ikm, salt, info, outLen)
	out2 := HKDFSHA256(ikm, salt, info, outLen)

	if len(out1) != outLen {
		t.Fatalf("expected len=%d, got %d", outLen, len(out1))
	}
	if !bytes.Equal(out1, out2) {
		t.Fatalf("HKDFSHA256 must be deterministic for same inputs")
	}

	out3 := HKDFSHA256(ikm, salt, []byte("different-info"), outLen)
	if bytes.Equal(out1, out3) {
		t.Fatalf("expected different output when info changes")
	}
}

func TestDerivePSK_DeterministicAndDifferent(t *testing.T) {
	u1, err := ParseUUID("11111111-1111-1111-1111-111111111111")
	if err != nil {
		t.Fatal(err)
	}
	u2, err := ParseUUID("22222222-2222-2222-2222-222222222222")
	if err != nil {
		t.Fatal(err)
	}

	psk1 := DerivePSK(u1)
	psk2 := DerivePSK(u1)
	psk3 := DerivePSK(u2)

	if psk1 != psk2 {
		t.Fatalf("DerivePSK must be deterministic for same userID")
	}
	if psk1 == psk3 {
		t.Fatalf("different userIDs should produce different PSKs")
	}
}
