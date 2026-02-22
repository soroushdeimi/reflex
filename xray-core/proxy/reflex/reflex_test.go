package reflex

import (
	"testing"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/reflex/encoding"
)

func TestProtocolName(t *testing.T) {
	if ProtocolName != "reflex" {
		t.Fatalf("ProtocolName = %q", ProtocolName)
	}
}

func TestConstants(t *testing.T) {
	if FrameTypeData == 0 || FrameTypeClose == 0 {
		t.Fatalf("frame constants must be non-zero")
	}
}

func TestAccountAsAccount(t *testing.T) {
	acc := &Account{ID: "00112233-4455-6677-8899-aabbccddeeff", Policy: "default"}
	parsed, err := acc.AsAccount()
	if err != nil {
		t.Fatalf("AsAccount failed: %v", err)
	}
	if parsed == nil {
		t.Fatalf("AsAccount returned nil")
	}
}

func TestMemoryValidatorAddGet(t *testing.T) {
	acc, err := (&Account{ID: "00112233-4455-6677-8899-aabbccddeeff"}).AsAccount()
	if err != nil {
		t.Fatalf("AsAccount failed: %v", err)
	}
	user := &protocol.MemoryUser{Account: acc, Email: "u@example.com"}

	v := NewMemoryValidator()
	if err := v.Add(user); err != nil {
		t.Fatalf("Add failed: %v", err)
	}
	if _, ok := v.Get("00112233-4455-6677-8899-aabbccddeeff"); !ok {
		t.Fatalf("Get failed")
	}
}

func TestDeriveSessionKey(t *testing.T) {
	var secret [32]byte
	copy(secret[:], []byte("shared-secret-12345678901234567890"))
	key, err := encoding.DeriveSessionKey(secret, []byte("salt"), []byte("info"))
	if err != nil {
		t.Fatalf("DeriveSessionKey failed: %v", err)
	}
	if key == [32]byte{} {
		t.Fatalf("key must not be zero")
	}
}

func TestGenerateKeyPair(t *testing.T) {
	kp, err := encoding.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	if kp.PublicKey == [32]byte{} {
		t.Fatalf("public key is empty")
	}
}

func TestTrafficProfileHelpers(t *testing.T) {
	p := &encoding.TrafficProfile{}
	p.SetNextPacketSize(900)
	if got := p.GetPacketSize(); got != 900 {
		t.Fatalf("GetPacketSize = %d", got)
	}
}

func TestSessionPadding(t *testing.T) {
	s := &encoding.Session{}
	out := s.AddPadding([]byte("hello"), 10)
	if len(out) != 10 {
		t.Fatalf("AddPadding len = %d", len(out))
	}
}
