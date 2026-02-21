package reflex

import (
	"crypto/sha256"
	"errors"

	"github.com/google/uuid"
)

// GetSharedSecret derives shared secret from user UUID
// For simplicity, we use UUID hash as the shared secret
func GetSharedSecret(userUUID string) ([]byte, error) {
	parsedUUID, err := uuid.Parse(userUUID)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256([]byte(parsedUUID.String()))
	return hash[:], nil
}

// UserIDToBytes converts UUID string to 16-byte array
func UserIDToBytes(userUUID string) ([16]byte, error) {
	var result [16]byte
	parsedUUID, err := uuid.Parse(userUUID)
	if err != nil {
		return result, err
	}
	copy(result[:], parsedUUID[:])
	return result, nil
}

// UserIDFromBytes converts 16-byte array to UUID string
func UserIDFromBytes(userID [16]byte) (string, error) {
	parsedUUID, err := uuid.FromBytes(userID[:])
	if err != nil {
		return "", err
	}
	return parsedUUID.String(), nil
}

// AuthenticateUser verifies user UUID exists in client list
func AuthenticateUser(userID [16]byte, userUUIDs []string) (string, error) {
	userIDStr, err := UserIDFromBytes(userID)
	if err != nil {
		return "", errors.New("invalid user ID format")
	}

	for _, uuid := range userUUIDs {
		if uuid == userIDStr {
			return uuid, nil
		}
	}

	return "", errors.New("user not found")
}
