package handshake

import (
	"crypto/sha256"
	"sync"
	"time"
)

// Security defaults for Step2.
//
// - AllowedClockSkew: how far client's timestamp may deviate from server time.
// - DefaultNonceTTL: how long a (userID, nonce) pair is considered "used".
//
// NOTE: These values can later be made configurable via config/proto if needed.
// For now, hard-coded defaults keep Step2 simple and reliable.
const (
	AllowedClockSkew = 2 * time.Minute
	DefaultNonceTTL  = 10 * time.Minute
)

// ValidateTimestamp checks that ts is within ±AllowedClockSkew of now.
// Caller should pass server-side now (time.Now()).
func ValidateTimestamp(now time.Time, ts int64) error {
	// Treat ts as unix seconds.
	clientTime := time.Unix(ts, 0)

	// abs(now - clientTime) <= AllowedClockSkew
	delta := now.Sub(clientTime)
	if delta < 0 {
		delta = -delta
	}
	if delta > AllowedClockSkew {
		return New(KindInvalidHandshake, "timestamp out of allowed window")
	}
	return nil
}

// ReplayCache prevents replay attacks by tracking seen (userID, nonce) pairs.
type ReplayCache struct {
	mu        sync.Mutex
	ttl       time.Duration
	entries   map[[32]byte]int64 // key -> expiresAt (unix seconds)
	ops       uint64             // operation counter
	purgeEach uint64             // purge every N operations
}

// NewReplayCache creates a replay cache with a given TTL.
// If ttl <= 0, DefaultNonceTTL is used.
func NewReplayCache(ttl time.Duration) *ReplayCache {
	if ttl <= 0 {
		ttl = DefaultNonceTTL
	}
	return &ReplayCache{
		ttl:       ttl,
		entries:   make(map[[32]byte]int64),
		purgeEach: 256, // lazy purge to keep memory bounded without goroutines
	}
}

// CheckAndMark checks if (userID, nonce) has been seen and not expired.
// If it is new, it marks it as seen and returns nil.
// If it is a replay, it returns KindReplay.
func (rc *ReplayCache) CheckAndMark(now time.Time, userID [UserIDSize]byte, nonce [NonceSize]byte) error {
	key := makeReplayKey(userID, nonce)
	nowSec := now.Unix()
	expSec := now.Add(rc.ttl).Unix()

	rc.mu.Lock()
	defer rc.mu.Unlock()

	rc.ops++
	if rc.purgeEach > 0 && rc.ops%rc.purgeEach == 0 {
		rc.purgeLocked(nowSec)
	}

	if oldExp, ok := rc.entries[key]; ok {
		// If still valid -> replay
		if oldExp >= nowSec {
			return New(KindReplay, "replayed nonce")
		}
		// Expired -> overwrite
	}

	rc.entries[key] = expSec
	return nil
}

// Size returns approximate number of cached entries.
func (rc *ReplayCache) Size() int {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return len(rc.entries)
}

func (rc *ReplayCache) purgeLocked(nowSec int64) {
	for k, exp := range rc.entries {
		if exp < nowSec {
			delete(rc.entries, k)
		}
	}
}

// makeReplayKey returns SHA-256(userID || nonce) as a fixed-size key.
func makeReplayKey(userID [UserIDSize]byte, nonce [NonceSize]byte) [32]byte {
	var buf [UserIDSize + NonceSize]byte
	copy(buf[:UserIDSize], userID[:])
	copy(buf[UserIDSize:], nonce[:])
	return sha256.Sum256(buf[:])
}
