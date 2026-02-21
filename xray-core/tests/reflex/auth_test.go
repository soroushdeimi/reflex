package reflex_test

import (
	"bytes"
	"testing"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/proxy/reflex"
)

var testUserUUID = "00000000-0000-0000-0000-000000000000"

func TestGetSharedSecret(t *testing.T) {
	secret, err := reflex.GetSharedSecret(testUserUUID)
	if err != nil {
		t.Fatalf("GetSharedSecret failed: %v", err)
	}

	if len(secret) != 32 {
		t.Errorf("secret length mismatch: got %d, want 32", len(secret))
	}

	// Should be deterministic
	secret2, _ := reflex.GetSharedSecret(testUserUUID)
	if !bytes.Equal(secret, secret2) {
		t.Error("shared secret should be deterministic")
	}
}

func TestGetSharedSecretInvalidUUID(t *testing.T) {
	_, err := reflex.GetSharedSecret("invalid-uuid")
	if err == nil {
		t.Fatal("should reject invalid UUID")
	}
}

func TestUserIDToBytes(t *testing.T) {
	userID, err := reflex.UserIDToBytes(testUserUUID)
	if err != nil {
		t.Fatalf("UserIDToBytes failed: %v", err)
	}

	parsedUUID, _ := uuid.Parse(testUserUUID)
	expected := [16]byte{}
	copy(expected[:], parsedUUID[:])

	if userID != expected {
		t.Error("user ID bytes mismatch")
	}
}

func TestUserIDFromBytes(t *testing.T) {
	userID, _ := reflex.UserIDToBytes(testUserUUID)
	uuidStr, err := reflex.UserIDFromBytes(userID)
	if err != nil {
		t.Fatalf("UserIDFromBytes failed: %v", err)
	}

	if uuidStr != testUserUUID {
		t.Errorf("UUID string mismatch: got %s, want %s", uuidStr, testUserUUID)
	}
}

func TestAuthenticateUser(t *testing.T) {
	userID, _ := reflex.UserIDToBytes(testUserUUID)
	userUUIDs := []string{testUserUUID, "11111111-1111-1111-1111-111111111111"}

	uuid, err := reflex.AuthenticateUser(userID, userUUIDs)
	if err != nil {
		t.Fatalf("AuthenticateUser failed: %v", err)
	}

	if uuid != testUserUUID {
		t.Errorf("UUID mismatch: got %s, want %s", uuid, testUserUUID)
	}
}

func TestAuthenticateUserNotFound(t *testing.T) {
	invalidUUID := "ffffffff-ffff-ffff-ffff-ffffffffffff"
	userID, _ := reflex.UserIDToBytes(invalidUUID)
	userUUIDs := []string{testUserUUID}

	_, err := reflex.AuthenticateUser(userID, userUUIDs)
	if err == nil {
		t.Fatal("should reject unknown user")
	}
}
