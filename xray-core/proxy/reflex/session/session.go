package session

import "github.com/xtls/xray-core/common/protocol"

// Session holds per-connection state after handshake.
type Session struct {
	// Derived symmetric key for AEAD encryption (Step 3)
	SessionKey []byte

	// Nonce counters (used in Step 3)
	WriteNonce uint64
	ReadNonce  uint64

	// Authenticated user
	User *protocol.MemoryUser
}
