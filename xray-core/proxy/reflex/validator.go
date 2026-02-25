package reflex

import (
	"sync"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/uuid"
)

// ClientInfo represents an authorized Reflex client.
//
// We keep it minimal for Step2 (Handshake + authentication). Later steps can
// extend it with per-user settings (e.g. morphing policy, custom PSK, etc.).
type ClientInfo struct {
	ID     uuid.UUID
	Policy string
}

// Validator provides a minimal interface for user authentication.
// We keep an interface here so inbound/outbound code stays decoupled from the
// in-memory implementation and can be swapped in tests or future extensions.
type Validator interface {
	// Get returns the client info by UUID bytes.
	Get(id [16]byte) (*ClientInfo, bool)
	// Count returns number of registered clients.
	Count() int
}

// MemoryValidator stores authorized clients in memory.
// Key is raw UUID bytes (16 bytes) for fast lookup.
type MemoryValidator struct {
	mu    sync.RWMutex
	users map[[16]byte]*ClientInfo
}

// NewMemoryValidator creates an empty validator.
func NewMemoryValidator() *MemoryValidator {
	return &MemoryValidator{users: make(map[[16]byte]*ClientInfo)}
}

// AddFromConfig registers a client from config values.
func (v *MemoryValidator) AddFromConfig(idStr, policy string) error {
	id, err := uuid.ParseString(idStr)
	if err != nil {
		return errors.New("invalid reflex client uuid").Base(err)
	}
	return v.Add(&ClientInfo{ID: id, Policy: policy})
}

// Add registers a client.
func (v *MemoryValidator) Add(c *ClientInfo) error {
	if c == nil {
		return errors.New("nil client")
	}
	var key [16]byte
	copy(key[:], c.ID.Bytes())

	v.mu.Lock()
	defer v.mu.Unlock()
	if _, exists := v.users[key]; exists {
		return errors.New("reflex client already exists")
	}
	v.users[key] = c
	return nil
}

// Get returns the client by UUID bytes.
func (v *MemoryValidator) Get(id [16]byte) (*ClientInfo, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	c, ok := v.users[id]
	return c, ok
}

// Count returns registered users count.
func (v *MemoryValidator) Count() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.users)
}
