package reflex

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// ParseUUID parses a UUID string (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx) into 16 bytes.
func ParseUUID(s string) ([16]byte, error) {
	var out [16]byte
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.ReplaceAll(s, "-", "")
	if len(s) != 32 {
		return out, fmt.Errorf("invalid UUID length")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return out, fmt.Errorf("invalid UUID hex: %w", err)
	}
	copy(out[:], b)
	return out, nil
}

// UUIDString formats 16 bytes into a canonical UUID string.
func UUIDString(u [16]byte) string {
	hexStr := hex.EncodeToString(u[:])
	// 8-4-4-4-12
	return fmt.Sprintf("%s-%s-%s-%s-%s", hexStr[0:8], hexStr[8:12], hexStr[12:16], hexStr[16:20], hexStr[20:32])
}
