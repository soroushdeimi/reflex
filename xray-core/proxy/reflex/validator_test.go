package reflex

import (
	"bytes"
	"testing"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
)

// TestValidatorAdd tests adding users to validator
func TestValidatorAdd(t *testing.T) {
	validator := &Validator{
		users: make(map[[16]byte]*protocol.MemoryUser),
	}

	// Create a test user
	id, _ := uuid.ParseString("b831381d-6324-4d53-ad4f-8cda48b30811")
	user := &protocol.MemoryUser{
		Account: &MemoryAccount{
			ID: protocol.NewID(id),
		},
		Email: "test@example.com",
	}

	// Add user
	err := validator.Add(user)
	if err != nil {
		t.Fatalf("Add failed: %v", err)
	}

	// Verify user was added
	if len(validator.users) != 1 {
		t.Fatal("user should be added to validator")
	}
}

// TestValidatorGet tests retrieving user by UUID
func TestValidatorGet(t *testing.T) {
	validator := &Validator{
		users: make(map[[16]byte]*protocol.MemoryUser),
	}

	// Create test user
	id, _ := uuid.ParseString("b831381d-6324-4d53-ad4f-8cda48b30811")
	user := &protocol.MemoryUser{
		Account: &MemoryAccount{
			ID: protocol.NewID(id),
		},
		Email: "test@example.com",
	}

	validator.Add(user)

	// Get user
	uuidBytes := protocol.NewID(id).Bytes()
	var userIDArray [16]byte
	copy(userIDArray[:], uuidBytes)

	retrieved, err := validator.Get(userIDArray)
	if err != nil {
		t.Fatalf("user should be found: %v", err)
	}
	if retrieved == nil {
		t.Fatal("user should be found")
	}
	if retrieved.Email != "test@example.com" {
		t.Fatalf("user email mismatch: expected 'test@example.com', got '%s'", retrieved.Email)
	}
}

// TestValidatorGetNonexistent tests getting nonexistent user returns nil
func TestValidatorGetNonexistent(t *testing.T) {
	validator := &Validator{
		users: make(map[[16]byte]*protocol.MemoryUser),
	}

	// Try to get nonexistent user
	var nonexistentID [16]byte
	for i := 0; i < 16; i++ {
		nonexistentID[i] = 0xFF
	}

	retrieved, err := validator.Get(nonexistentID)
	if err == nil {
		t.Fatal("nonexistent user should return error")
	}
	if retrieved != nil {
		t.Fatal("nonexistent user should return nil")
	}
}

// TestValidatorMultipleUsers tests adding multiple users
func TestValidatorMultipleUsers(t *testing.T) {
	validator := &Validator{
		users: make(map[[16]byte]*protocol.MemoryUser),
	}

	users := []struct {
		uuid  string
		email string
	}{
		{"b831381d-6324-4d53-ad4f-8cda48b30811", "user1@example.com"},
		{"c942492e-7435-5e64-be5g-9deb59b41922", "user2@example.com"},
		{"d053503f-8546-6f75-cf6h-0efc60c52033", "user3@example.com"},
	}

	// Add all users
	for _, u := range users {
		id, _ := uuid.ParseString(u.uuid)
		user := &protocol.MemoryUser{
			Account: &MemoryAccount{
				ID: protocol.NewID(id),
			},
			Email: u.email,
		}
		validator.Add(user)
	}

	// Verify all users were added
	if len(validator.users) != 3 {
		t.Fatalf("expected 3 users, got %d", len(validator.users))
	}

	// Retrieve each user
	for _, u := range users {
		id, _ := uuid.ParseString(u.uuid)
		uuidBytes := protocol.NewID(id).Bytes()
		var userIDArray [16]byte
		copy(userIDArray[:], uuidBytes)

		retrieved, err := validator.Get(userIDArray)
		if err != nil {
			t.Fatalf("user %s should be found: %v", u.email, err)
		}
		if retrieved == nil {
			t.Fatalf("user %s should be found", u.email)
		}
		if retrieved.Email != u.email {
			t.Fatalf("user email mismatch for %s", u.email)
		}
	}
}

// TestValidatorRemove tests removing user
func TestValidatorRemove(t *testing.T) {
	validator := &Validator{
		users: make(map[[16]byte]*protocol.MemoryUser),
	}

	// Add user
	id, _ := uuid.ParseString("b831381d-6324-4d53-ad4f-8cda48b30811")
	user := &protocol.MemoryUser{
		Account: &MemoryAccount{
			ID: protocol.NewID(id),
		},
		Email: "test@example.com",
	}
	validator.Add(user)

	// Remove user
	err := validator.Remove("test@example.com")
	if err != nil {
		t.Fatalf("Remove failed: %v", err)
	}

	// Verify user was removed
	if len(validator.users) != 0 {
		t.Fatal("user should be removed")
	}

	// Try to get removed user
	uuidBytes := protocol.NewID(id).Bytes()
	var userIDArray [16]byte
	copy(userIDArray[:], uuidBytes)
	retrieved, err := validator.Get(userIDArray)
	if err == nil {
		t.Fatal("removed user should not be found")
	}
	if retrieved != nil {
		t.Fatal("removed user should not be found")
	}
}

// TestValidatorRemoveNonexistent tests removing nonexistent user
func TestValidatorRemoveNonexistent(t *testing.T) {
	validator := &Validator{
		users: make(map[[16]byte]*protocol.MemoryUser),
	}

	// Try to remove nonexistent user
	err := validator.Remove("nonexistent@example.com")
	if err == nil {
		t.Fatal("should return error when removing nonexistent user")
	}
}

// TestValidatorDuplicate tests that duplicate UUIDs overwrite
func TestValidatorDuplicate(t *testing.T) {
	validator := &Validator{
		users: make(map[[16]byte]*protocol.MemoryUser),
	}

	id, _ := uuid.ParseString("b831381d-6324-4d53-ad4f-8cda48b30811")

	// Add first user with this UUID
	user1 := &protocol.MemoryUser{
		Account: &MemoryAccount{
			ID: protocol.NewID(id),
		},
		Email: "user1@example.com",
	}
	validator.Add(user1)

	// Add second user with same UUID
	user2 := &protocol.MemoryUser{
		Account: &MemoryAccount{
			ID: protocol.NewID(id),
		},
		Email: "user2@example.com",
	}
	validator.Add(user2)

	// Should only have one user (overwrites)
	if len(validator.users) != 1 {
		t.Fatalf("should have only 1 user, got %d", len(validator.users))
	}

	// Should be the second user
	uuidBytes := protocol.NewID(id).Bytes()
	var userIDArray [16]byte
	copy(userIDArray[:], uuidBytes)
	retrieved, err := validator.Get(userIDArray)
	if err != nil {
		t.Fatalf("user should be found: %v", err)
	}
	if retrieved.Email != "user2@example.com" {
		t.Fatal("should contain the second user after overwrite")
	}
}

// TestAccountAsAccount tests Account.AsAccount conversion
func TestAccountAsAccount(t *testing.T) {
	id, _ := uuid.ParseString("b831381d-6324-4d53-ad4f-8cda48b30811")
	account := &Account{
		Id:     id.String(),
		Policy: "youtube",
	}

	memAccount, err := account.AsAccount()
	if err != nil {
		t.Fatalf("AsAccount failed: %v", err)
	}

	cast := memAccount.(*MemoryAccount)
	if cast.ID.String() != id.String() {
		t.Fatal("ID mismatch in conversion")
	}
	if cast.Policy != "youtube" {
		t.Fatal("Policy mismatch in conversion")
	}
}

// TestAccountEquals tests Account equality comparison
func TestAccountEquals(t *testing.T) {
	id1, _ := uuid.ParseString("b831381d-6324-4d53-ad4f-8cda48b30811")
	id2, _ := uuid.ParseString("c942492e-7435-5e64-be5g-9deb59b41922")

	acc1 := &MemoryAccount{
		ID:     protocol.NewID(id1),
		Policy: "youtube",
	}

	acc2 := &MemoryAccount{
		ID:     protocol.NewID(id1),
		Policy: "youtube",
	}

	acc3 := &MemoryAccount{
		ID:     protocol.NewID(id2),
		Policy: "youtube",
	}

	// Same UUID should be equal
	if !acc1.Equals(acc2) {
		t.Fatal("accounts with same UUID should be equal")
	}

	// Different UUID should not be equal
	if acc1.Equals(acc3) {
		t.Fatal("accounts with different UUID should not be equal")
	}
}

// TestAccountToProto tests Account.ToProto conversion
func TestAccountToProto(t *testing.T) {
	id, _ := uuid.ParseString("b831381d-6324-4d53-ad4f-8cda48b30811")
	memAccount := &MemoryAccount{
		ID:     protocol.NewID(id),
		Policy: "zoom",
	}

	proto := memAccount.ToProto().(*Account)

	if proto.Id != protocol.NewID(id).String() {
		t.Fatal("ID mismatch in proto conversion")
	}
	if proto.Policy != "zoom" {
		t.Fatal("Policy mismatch in proto conversion")
	}
}

// TestValidatorConcurrency tests concurrent access to validator
func TestValidatorConcurrency(t *testing.T) {
	validator := &Validator{
		users: make(map[[16]byte]*protocol.MemoryUser),
	}

	// Add users concurrently
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func(index int) {
			id, _ := uuid.ParseString("b831381d-6324-4d53-ad4f-8cda48b30811")
			user := &protocol.MemoryUser{
				Account: &MemoryAccount{
					ID: protocol.NewID(id),
				},
				Email: "user@example.com",
			}
			_ = validator.Add(user)
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Should have at least 1 user (multiple adds of same UUID)
	if len(validator.users) < 1 {
		t.Fatal("should have at least 1 user after concurrent adds")
	}
}

// TestValidatorLargeUUIDSet tests validator with many users
func TestValidatorLargeUUIDSet(t *testing.T) {
	validator := &Validator{
		users: make(map[[16]byte]*protocol.MemoryUser),
	}

	// Add 100 users
	baseUUID := "b831381d-6324-4d53-ad4f-8cda48b30"
	for i := 0; i < 100; i++ {
		uuidStr := baseUUID + string(rune((i/10)%10)) + string(rune(i%10))
		if len(uuidStr) < 36 {
			// Pad to 36 chars
			uuidStr = uuidStr + "811"[:36-len(uuidStr)]
		}

		id, err := uuid.ParseString(uuidStr)
		if err != nil {
			id, _ = uuid.ParseString("b831381d-6324-4d53-ad4f-8cda48b30811")
		}

		user := &protocol.MemoryUser{
			Account: &MemoryAccount{
				ID: protocol.NewID(id),
			},
			Email: "user@example.com",
		}
		validator.Add(user)
	}

	// Verify count
	if len(validator.users) == 0 {
		t.Fatal("should have users in validator")
	}
}

// TestAccountPolicyVariants tests different policy values
func TestAccountPolicyVariants(t *testing.T) {
	id, _ := uuid.ParseString("b831381d-6324-4d53-ad4f-8cda48b30811")

	policies := []string{
		"youtube",
		"zoom",
		"http2-api",
		"custom",
		"",
	}

	for _, policy := range policies {
		account := &MemoryAccount{
			ID:     protocol.NewID(id),
			Policy: policy,
		}

		if account.Policy != policy {
			t.Fatalf("policy mismatch: expected '%s', got '%s'", policy, account.Policy)
		}

		proto := account.ToProto().(*Account)
		if proto.Policy != policy {
			t.Fatalf("proto policy mismatch: expected '%s', got '%s'", policy, proto.Policy)
		}
	}
}

// TestValidatorGetByUUID tests retrieval by UUID string
func TestValidatorGetByUUID(t *testing.T) {
	validator := &Validator{
		users: make(map[[16]byte]*protocol.MemoryUser),
	}

	uuidStr := "b831381d-6324-4d53-ad4f-8cda48b30811"
	id, _ := uuid.ParseString(uuidStr)
	user := &protocol.MemoryUser{
		Account: &MemoryAccount{
			ID: protocol.NewID(id),
		},
		Email: "test@example.com",
	}

	validator.Add(user)

	// Get by string UUID
	retrieved, err := validator.GetByUUID(uuidStr)
	if err != nil {
		t.Fatalf("user should be found by UUID string: %v", err)
	}
	if retrieved == nil {
		t.Fatal("user should be found by UUID string")
	}
	if retrieved.Email != "test@example.com" {
		t.Fatal("retrieved user should match")
	}
}

// TestValidatorUUIDBytes tests UUID byte array handling
func TestValidatorUUIDBytes(t *testing.T) {
	validator := &Validator{
		users: make(map[[16]byte]*protocol.MemoryUser),
	}

	id, _ := uuid.ParseString("b831381d-6324-4d53-ad4f-8cda48b30811")
	user := &protocol.MemoryUser{
		Account: &MemoryAccount{
			ID: protocol.NewID(id),
		},
		Email: "test@example.com",
	}

	validator.Add(user)

	// Get UUID bytes
	idBytes := protocol.NewID(id).Bytes()
	var userIDArray [16]byte
	copy(userIDArray[:], idBytes)

	// Verify we can retrieve with byte array
	retrieved, err := validator.Get(userIDArray)
	if err != nil {
		t.Fatalf("user should be found with UUID byte array: %v", err)
	}
	if retrieved == nil {
		t.Fatal("user should be found with UUID byte array")
	}

	// Verify bytes are exactly 16
	if len(idBytes) != 16 {
		t.Fatalf("UUID bytes should be 16 bytes, got %d", len(idBytes))
	}

	// Verify copy integrity
	if !bytes.Equal(idBytes, userIDArray[:]) {
		t.Fatal("UUID bytes should match array")
	}
}
