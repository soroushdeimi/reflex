package reflex

import (
	"sync"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
)

// Validator stores valid Reflex users
type Validator struct {
	sync.RWMutex
	users map[[16]byte]*protocol.MemoryUser
}

// NewValidator creates a new user validator
func NewValidator() *Validator {
	return &Validator{
		users: make(map[[16]byte]*protocol.MemoryUser),
	}
}

// Add adds a user to the validator
func (v *Validator) Add(u *protocol.MemoryUser) error {
	v.Lock()
	defer v.Unlock()

	account := u.Account.(*MemoryAccount)
	idBytes := account.ID.Bytes()
	var idArray [16]byte
	copy(idArray[:], idBytes)
	v.users[idArray] = u
	return nil
}

// Get retrieves a user by UUID bytes
func (v *Validator) Get(userID [16]byte) (*protocol.MemoryUser, error) {
	v.RLock()
	defer v.RUnlock()

	if user, found := v.users[userID]; found {
		return user, nil
	}
	return nil, errors.New("user not found")
}

// GetByUUID retrieves a user by UUID string
func (v *Validator) GetByUUID(id string) (*protocol.MemoryUser, error) {
	parsedID, err := uuid.ParseString(id)
	if err != nil {
		return nil, errors.New("invalid UUID")
	}

	idBytes := parsedID.Bytes()
	var idArray [16]byte
	copy(idArray[:], idBytes)
	return v.Get(idArray)
}

// Remove removes a user from the validator
func (v *Validator) Remove(email string) error {
	v.Lock()
	defer v.Unlock()

	for id, user := range v.users {
		if user.Email == email {
			delete(v.users, id)
			return nil
		}
	}
	return errors.New("user not found")
}
