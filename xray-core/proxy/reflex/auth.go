package reflex

import (
	"errors"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
)

func authenticateUser(userID [16]byte, users []*protocol.MemoryUser) (*protocol.MemoryUser, error) {
	u := uuid.UUID(userID)

	targetID := protocol.NewID(u)

	for _, user := range users {
		if user.Account.Equals(targetID) {
			return user, nil
		}
	}

	return nil, errors.New("user not found")
}
