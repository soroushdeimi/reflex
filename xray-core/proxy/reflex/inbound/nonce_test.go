package inbound

import (
	"testing"
	"time"
)

func TestNonceCache_AllowsFirstUse(t *testing.T) {
	c := NewNonceCache(1000, 10*time.Minute)

	var userID [16]byte
	var nonce [16]byte
	userID[0] = 1
	nonce[0] = 9

	if ok := c.Check(userID, nonce, time.Now()); !ok {
		t.Fatalf("expected first nonce use to be allowed")
	}
}

func TestNonceCache_RejectsReplay(t *testing.T) {
	c := NewNonceCache(1000, 10*time.Minute)

	var userID [16]byte
	var nonce [16]byte
	userID[0] = 2
	nonce[0] = 7

	now := time.Now()
	if ok := c.Check(userID, nonce, now); !ok {
		t.Fatalf("expected first nonce use to be allowed")
	}
	if ok := c.Check(userID, nonce, now.Add(1*time.Second)); ok {
		t.Fatalf("expected replay nonce to be rejected")
	}
}

func TestNonceCache_ExpiresAfterTTL(t *testing.T) {
	c := NewNonceCache(1000, 50*time.Millisecond)

	var userID [16]byte
	var nonce [16]byte
	userID[0] = 3
	nonce[0] = 5

	now := time.Now()
	if ok := c.Check(userID, nonce, now); !ok {
		t.Fatalf("expected first nonce use to be allowed")
	}

	// wait for TTL to pass, then it should be accepted again (after cleanup)
	time.Sleep(80 * time.Millisecond)
	if ok := c.Check(userID, nonce, time.Now()); !ok {
		t.Fatalf("expected nonce to be accepted after TTL expiry")
	}
}
