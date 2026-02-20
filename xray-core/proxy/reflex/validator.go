package reflex

import (
	"sync"

	"github.com/xtls/xray-core/common/protocol"
)

// Validator stores users for a reflex connection
type Validator interface {
	// Add adds a user to the validator
	Add(user *protocol.MemoryUser) error
	// Get gets a user by ID
	Get(id string) (*protocol.MemoryUser, bool)
}

// MemoryValidator is an in-memory implementation of Validator
type MemoryValidator struct {
	users sync.Map
}

// Add adds a user to the validator
func (v *MemoryValidator) Add(user *protocol.MemoryUser) error {
	if user == nil {
		return newError("user is nil")
	}

	acc, ok := user.Account.(*MemoryAccount)
	if !ok {
		return newError("invalid account type")
	}

	v.users.Store(acc.ID.String(), user)
	return nil
}

// Get gets a user by ID
func (v *MemoryValidator) Get(id string) (*protocol.MemoryUser, bool) {
	if val, ok := v.users.Load(id); ok {
		return val.(*protocol.MemoryUser), true
	}
	return nil, false
}

// NewMemoryValidator creates a new MemoryValidator
func NewMemoryValidator() *MemoryValidator {
	return &MemoryValidator{}
}
