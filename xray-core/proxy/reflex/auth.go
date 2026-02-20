package reflex

import (
	"errors"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
)

// authenticateUser searches for a user in the list by UUID
func authenticateUser(userID [16]byte, users []*protocol.MemoryUser) (*protocol.MemoryUser, error) {
	// Convert bytes to internal UUID type
	u := uuid.UUID(userID)

	// Create a target ID object for comparison
	targetID := protocol.NewID(u)

	for _, user := range users {
		// Extract ID from account interface using AsID()
		if account, ok := user.Account.(interface{ AsID() *protocol.ID }); ok {
			// Compare IDs
			if account.AsID().Equals(targetID) {
				return user, nil
			}
		}
	}

	return nil, errors.New("user not found")
}
