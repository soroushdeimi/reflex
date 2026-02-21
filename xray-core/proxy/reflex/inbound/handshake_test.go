package inbound

import (
	"bytes"
	"testing"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common/protocol"
)

func TestIsReflexMagic(t *testing.T) {
	h := &Handler{}

	if h.isReflexMagic([]byte{0x00, 0x01}) {
		t.Fatal("expected false for short input")
	}

	// "REFX" => 0x52 0x46 0x58 0x4C
	if !h.isReflexMagic([]byte{0x52, 0x46, 0x58, 0x4C}) {
		t.Fatal("expected true for Reflex magic")
	}

	if h.isReflexMagic([]byte{0x52, 0x46, 0x58, 0x4D}) {
		t.Fatal("expected false for wrong magic")
	}
}

func TestAuthenticateUser_OK(t *testing.T) {
	id := uuid.MustParse("11111111-1111-1111-1111-111111111111")

	h := &Handler{
		clients: []*protocol.MemoryUser{
			{
				Email:   id.String(),
				Account: &MemoryAccount{Id: id.String()},
			},
		},
	}

	var userID [16]byte
	copy(userID[:], id[:])

	u, err := h.authenticateUser(userID)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if u == nil {
		t.Fatal("expected non-nil user")
	}
}

func TestAuthenticateUser_Fail(t *testing.T) {
	id := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	other := uuid.MustParse("22222222-2222-2222-2222-222222222222")

	h := &Handler{
		clients: []*protocol.MemoryUser{
			{
				Email:   id.String(),
				Account: &MemoryAccount{Id: id.String()},
			},
		},
	}

	var userID [16]byte
	copy(userID[:], other[:])

	if _, err := h.authenticateUser(userID); err == nil {
		t.Fatal("expected error for unknown user")
	}
}

func TestAuthenticateUserBytes_OK(t *testing.T) {
	id := uuid.MustParse("11111111-1111-1111-1111-111111111111")

	h := &Handler{
		clients: []*protocol.MemoryUser{
			{
				Email:   id.String(),
				Account: &MemoryAccount{Id: id.String()},
			},
		},
	}

	var userID [16]byte
	copy(userID[:], id[:])

	u, err := h.authenticateUserBytes(userID)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if u == nil {
		t.Fatal("expected non-nil user")
	}
}

func TestDeriveSharedKey_Symmetric(t *testing.T) {
	priv1, pub1, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	priv2, pub2, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	s1 := deriveSharedKey(priv1, pub2)
	s2 := deriveSharedKey(priv2, pub1)

	if !bytes.Equal(s1[:], s2[:]) {
		t.Fatal("shared key mismatch")
	}
}

func TestDeriveSessionKey_LengthAndDeterminism(t *testing.T) {
	var shared [32]byte
	for i := range shared {
		shared[i] = byte(i)
	}

	k1 := deriveSessionKey(shared, []byte("reflex-session"))
	k2 := deriveSessionKey(shared, []byte("reflex-session"))

	if len(k1) != 32 {
		t.Fatalf("expected 32-byte session key, got %d", len(k1))
	}
	if !bytes.Equal(k1, k2) {
		t.Fatal("expected deterministic session key for same inputs")
	}
}