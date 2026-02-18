package inbound

import (
	"testing"
	"time"
)

func TestTrafficProfileGetPacketSize(t *testing.T) {
	p := DefaultProfile
	if p == nil {
		t.Fatal("DefaultProfile is nil")
	}
	for i := 0; i < 50; i++ {
		size := p.GetPacketSize()
		if size <= 0 {
			t.Errorf("GetPacketSize() = %d", size)
		}
	}
	p.SetNextPacketSize(999)
	if p.GetPacketSize() != 999 {
		t.Errorf("override: got %d, want 999", p.GetPacketSize())
	}
	// After use, next is from distribution again (not 999)
	_ = p.GetPacketSize()
}

func TestTrafficProfileGetDelay(t *testing.T) {
	p := DefaultProfile
	for i := 0; i < 20; i++ {
		d := p.GetDelay()
		if d < 0 {
			t.Errorf("GetDelay() = %v", d)
		}
	}
	p.SetNextDelay(100 * time.Millisecond)
	if p.GetDelay() != 100*time.Millisecond {
		t.Errorf("override: got %v", p.GetDelay())
	}
}

func TestApplyMorphing(t *testing.T) {
	p := DefaultProfile
	data := []byte("short")
	out, delay := p.ApplyMorphing(data)
	if len(out) < len(data) {
		t.Errorf("morphed length %d < input %d", len(out), len(data))
	}
	if delay < 0 {
		t.Errorf("delay = %v", delay)
	}
	// Nil profile: no padding
	out2, delay2 := (*TrafficProfile)(nil).ApplyMorphing(data)
	if !bytesEqual(out2, data) {
		t.Error("nil profile should return data unchanged")
	}
	if delay2 != 0 {
		t.Errorf("nil profile delay = %v", delay2)
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
