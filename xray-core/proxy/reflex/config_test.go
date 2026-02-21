package reflex

import (
	"testing"
)

func TestAccountAsAccount(t *testing.T) {
	account := &Account{Id: "b831381d-6324-4d53-ad4f-8cda48b30811"}
	memAccount, err := account.AsAccount()
	if err != nil {
		t.Fatalf("AsAccount failed: %v", err)
	}

	ma, ok := memAccount.(*MemoryAccount)
	if !ok {
		t.Fatal("expected *MemoryAccount type")
	}
	if ma.ID != "b831381d-6324-4d53-ad4f-8cda48b30811" {
		t.Fatalf("expected matching ID, got %s", ma.ID)
	}
}

func TestMemoryAccountEquals(t *testing.T) {
	a1 := &MemoryAccount{ID: "abc-123"}
	a2 := &MemoryAccount{ID: "abc-123"}
	a3 := &MemoryAccount{ID: "different"}

	if !a1.Equals(a2) {
		t.Fatal("identical accounts should be equal")
	}
	if a1.Equals(a3) {
		t.Fatal("different accounts should not be equal")
	}
}

func TestMemoryAccountEqualsWrongType(t *testing.T) {
	a := &MemoryAccount{ID: "test"}
	if a.Equals(nil) {
		t.Fatal("should return false for nil")
	}
}

func TestMemoryAccountToProto(t *testing.T) {
	ma := &MemoryAccount{ID: "proto-test-id"}
	msg := ma.ToProto()
	if msg == nil {
		t.Fatal("ToProto returned nil")
	}

	account, ok := msg.(*Account)
	if !ok {
		t.Fatal("expected *Account type")
	}
	if account.GetId() != "proto-test-id" {
		t.Fatalf("expected 'proto-test-id', got %s", account.GetId())
	}
}

func TestAccountProtoFields(t *testing.T) {
	account := &Account{Id: "test-id"}
	if account.GetId() != "test-id" {
		t.Fatal("GetId mismatch")
	}
}

func TestInboundConfigProtoFields(t *testing.T) {
	config := &InboundConfig{
		Clients: []*User{
			{Id: "user-1", Policy: "youtube"},
			{Id: "user-2", Policy: "zoom"},
		},
		Fallback: &Fallback{Dest: 8080},
	}

	clients := config.GetClients()
	if len(clients) != 2 {
		t.Fatalf("expected 2 clients, got %d", len(clients))
	}
	if clients[0].GetId() != "user-1" {
		t.Fatal("first client ID mismatch")
	}
	if clients[0].GetPolicy() != "youtube" {
		t.Fatal("first client policy mismatch")
	}

	fb := config.GetFallback()
	if fb == nil {
		t.Fatal("fallback is nil")
	}
	if fb.GetDest() != 8080 {
		t.Fatalf("expected fallback dest 8080, got %d", fb.GetDest())
	}
}

func TestOutboundConfigProtoFields(t *testing.T) {
	config := &OutboundConfig{
		Address: "127.0.0.1",
		Port:    443,
		Id:      "client-uuid",
		Policy:  "netflix",
	}

	if config.GetAddress() != "127.0.0.1" {
		t.Fatal("address mismatch")
	}
	if config.GetPort() != 443 {
		t.Fatal("port mismatch")
	}
	if config.GetId() != "client-uuid" {
		t.Fatal("ID mismatch")
	}
	if config.GetPolicy() != "netflix" {
		t.Fatal("policy mismatch")
	}
}
