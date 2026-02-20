package reflex

import (
	"bytes"
	"testing"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
)

// MockAccount to satisfy the interface used in auth.go
type MockAccount struct {
	protocol.Account
	id *protocol.ID
}

func (m *MockAccount) AsID() *protocol.ID {
	return m.id
}

// Test key pair generation and shared key derivation
func TestCryptoLogic(t *testing.T) {
	// 1. Generate keys
	privC, pubC, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	privS, pubS, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// 2. Derive shared keys
	sharedC := deriveSharedKey(privC, pubS)
	sharedS := deriveSharedKey(privS, pubC)

	if !bytes.Equal(sharedC[:], sharedS[:]) {
		t.Error("Shared keys do not match")
	}

	// 3. Derive session keys
	salt := []byte("test-salt")
	keyC, _ := deriveSessionKey(sharedC, salt)
	keyS, _ := deriveSessionKey(sharedS, salt)

	if !bytes.Equal(keyC, keyS) {
		t.Error("Session keys do not match")
	}
}

// Test user authentication logic
func TestAuthentication(t *testing.T) {
	testUUID := uuid.New()
	userID := [16]byte(testUUID)

	// Create a valid ID using the constructor
	targetID := protocol.NewID(testUUID)

	// Mock a user list using MockAccount
	users := []*protocol.MemoryUser{
		{
			Account: &MockAccount{
				id: targetID,
			},
		},
	}

	// 1. Test successful auth
	user, err := authenticateUser(userID, users)
	if err != nil {
		t.Errorf("Authentication failed: %v", err)
	}
	if user == nil {
		t.Error("User should not be nil")
	}

	// 2. Test failed auth
	wrongID := [16]byte(uuid.New())
	_, err = authenticateUser(wrongID, users)
	if err == nil {
		t.Error("Expected error for non-existent user")
	}
}
