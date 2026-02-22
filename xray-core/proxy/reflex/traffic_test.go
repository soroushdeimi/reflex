package reflex

import (
	"testing"
	"time"
)

func TestTrafficProfile_NextOverrides(t *testing.T) {
	p := CloneProfile("http2-api")
	if p == nil {
		t.Fatal("profile not found")
	}

	p.SetNextPacketSize(123)
	if got := p.GetPacketSize(); got != 123 {
		t.Fatalf("packet size mismatch: got %d want %d", got, 123)
	}

	p.SetNextDelay(15 * time.Millisecond)
	if got := p.GetDelay(); got != 15*time.Millisecond {
		t.Fatalf("delay mismatch: got %v want %v", got, 15*time.Millisecond)
	}
}

func TestTrafficProfile_CloneIsIndependent(t *testing.T) {
	p1 := CloneProfile("http2-api")
	p2 := CloneProfile("http2-api")
	if p1 == nil || p2 == nil {
		t.Fatal("profile not found")
	}

	p1.SetNextPacketSize(111)
	p2.SetNextPacketSize(222)

	if p1.GetPacketSize() != 111 || p2.GetPacketSize() != 222 {
		t.Fatal("clone instances should be independent")
	}
}
