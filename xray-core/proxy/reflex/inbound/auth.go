package inbound

import (
	//"encoding/binary"
	"errors"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common/protocol"
)

func (h *Handler) authenticateUser(userID [16]byte) (*protocol.MemoryUser, error) {
	// تبدیل [16]byte به string UUID
	userIDStr := uuid.UUID(userID).String()

	for _, user := range h.clients {
		if user.Account.(*MemoryAccount).Id == userIDStr {
			return user, nil
		}
	}
	return nil, errors.New("user not found")
}

// یا اگه می‌خوای مستقیماً با [16]byte کار کنی:
func (h *Handler) authenticateUserBytes(userID [16]byte) (*protocol.MemoryUser, error) {
	for _, user := range h.clients {
		accountID := user.Account.(*MemoryAccount).Id
		// تبدیل string UUID به [16]byte و مقایسه
		parsedUUID, err := uuid.Parse(accountID)
		if err != nil {
			continue
		}
		if parsedUUID == uuid.UUID(userID) {
			return user, nil
		}
	}
	return nil, errors.New("user not found")
}
