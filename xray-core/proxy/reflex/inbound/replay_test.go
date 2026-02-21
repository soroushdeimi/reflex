package inbound

import (
	"testing"
	"time"
)

func TestReplayCache_SeenOrAdd(t *testing.T) {
	c := newReplayCache(2 * time.Second)

	var n [16]byte
	n[0] = 1

	now := time.Now().Unix()

	if c.SeenOrAdd(n, now) {
		t.Fatal("first SeenOrAdd should return false")
	}
	if !c.SeenOrAdd(n, now) {
		t.Fatal("second SeenOrAdd should return true (replay)")
	}
}

func TestReplayCache_Expires(t *testing.T) {
	c := newReplayCache(1 * time.Second)

	var n [16]byte
	n[0] = 2

	now := time.Now().Unix()

	if c.SeenOrAdd(n, now) {
		t.Fatal("first should be false")
	}

	// simulate time pass beyond TTL
	if c.SeenOrAdd(n, now+2) {
		t.Fatal("should be false after expiry (nonce removed)")
	}
}