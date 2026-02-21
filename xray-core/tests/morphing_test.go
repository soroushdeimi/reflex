package reflex_test

import (
	"testing"
	"time"
	"github.com/xtls/xray-core/proxy/reflex"
)

func TestGetPacketSize(t *testing.T) {
	p := &reflex.TrafficProfile{
		PacketSizes: []reflex.PacketSizeDist{
			{Size: 100, Weight: 0.5},
			{Size: 200, Weight: 0.5},
		},
	}

	found100 := false
	found200 := false

	for i := 0; i < 100; i++ {
		size := p.GetPacketSize()
		if size == 100 {
			found100 = true
		} else if size == 200 {
			found200 = true
		} else {
			t.Errorf("unexpected size: %d", size)
		}
	}

	if !found100 || !found200 {
		t.Error("distribution failed to return all weighted sizes")
	}
}

func TestGetDelay(t *testing.T) {
	p := &reflex.TrafficProfile{
		Delays: []reflex.DelayDist{
			{Delay: time.Millisecond, Weight: 0.5},
			{Delay: 2 * time.Millisecond, Weight: 0.5},
		},
	}

	found1 := false
	found2 := false

	for i := 0; i < 100; i++ {
		delay := p.GetDelay()
		if delay == time.Millisecond {
			found1 = true
		} else if delay == 2*time.Millisecond {
			found2 = true
		} else {
			t.Errorf("unexpected delay: %v", delay)
		}
	}

	if !found1 || !found2 {
		t.Error("distribution failed to return all weighted delays")
	}
}
