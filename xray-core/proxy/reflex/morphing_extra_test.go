package reflex

import (
	"testing"
	"time"
)

func TestGetDelay_RandomDistribution(t *testing.T) {
	profile := Profiles["youtube"]
	// Run many times to verify delay is one of the defined values
	for i := 0; i < 1000; i++ {
		d := profile.GetDelay()
		found := false
		for _, dist := range profile.Delays {
			if d == dist.Delay {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("GetDelay() returned unexpected value: %v", d)
		}
	}
}

func TestGetDelay_UsesNextDelay(t *testing.T) {
	profile := &TrafficProfile{
		PacketSizes: []PacketSizeDist{{Size: 1000, Weight: 1.0}},
		Delays:      []DelayDist{{Delay: 10 * time.Millisecond, Weight: 1.0}},
	}

	expected := 777 * time.Millisecond
	profile.SetNextDelay(expected)

	got := profile.GetDelay()
	if got != expected {
		t.Errorf("GetDelay() after SetNextDelay = %v, want %v", got, expected)
	}

	// After consuming the deferred delay, nextDelay should be reset
	got2 := profile.GetDelay()
	if got2 == expected {
		t.Logf("Second GetDelay = %v (should return from distribution)", got2)
	}
	// Second call should be from distribution (10ms)
	if got2 != 10*time.Millisecond {
		t.Errorf("second GetDelay() = %v, want 10ms (from distribution)", got2)
	}
}

func TestGetDelay_ZoomProfile(t *testing.T) {
	profile := Profiles["zoom"]
	d := profile.GetDelay()
	if d == 0 {
		t.Error("GetDelay() should not return 0 for zoom profile")
	}
	// Verify within valid range for zoom profile
	found := false
	for _, dist := range profile.Delays {
		if d == dist.Delay {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("GetDelay() returned value not in zoom profile: %v", d)
	}
}

func TestSetNextPacketSize(t *testing.T) {
	profile := &TrafficProfile{
		PacketSizes: []PacketSizeDist{{Size: 1000, Weight: 1.0}},
		Delays:      []DelayDist{{Delay: 10 * time.Millisecond, Weight: 1.0}},
	}

	profile.SetNextPacketSize(1234)
	got := profile.GetPacketSize()
	if got != 1234 {
		t.Errorf("GetPacketSize() after SetNextPacketSize(1234) = %d, want 1234", got)
	}

	// After consuming the overridden value, should return from distribution
	got2 := profile.GetPacketSize()
	if got2 != 1000 {
		t.Errorf("second GetPacketSize() = %d, want 1000 (from distribution)", got2)
	}
}

func TestSetNextDelay(t *testing.T) {
	profile := &TrafficProfile{
		PacketSizes: []PacketSizeDist{{Size: 500, Weight: 1.0}},
		Delays:      []DelayDist{{Delay: 20 * time.Millisecond, Weight: 1.0}},
	}

	profile.SetNextDelay(500 * time.Millisecond)
	got := profile.GetDelay()
	if got != 500*time.Millisecond {
		t.Errorf("GetDelay() after SetNextDelay = %v, want 500ms", got)
	}
}

func TestSetNextDelay_ZeroValue(t *testing.T) {
	profile := &TrafficProfile{
		PacketSizes: []PacketSizeDist{{Size: 500, Weight: 1.0}},
		Delays:      []DelayDist{{Delay: 5 * time.Millisecond, Weight: 1.0}},
	}
	// SetNextDelay(0) should not override since GetDelay checks nextDelay > 0
	profile.SetNextDelay(0)
	got := profile.GetDelay()
	// Should return from distribution since nextDelay == 0 is not used
	if got != 5*time.Millisecond {
		t.Errorf("GetDelay() after SetNextDelay(0) = %v, want 5ms (from distribution)", got)
	}
}

func TestSetNextPacketSize_Zero(t *testing.T) {
	profile := &TrafficProfile{
		PacketSizes: []PacketSizeDist{{Size: 800, Weight: 1.0}},
		Delays:      []DelayDist{{Delay: 10 * time.Millisecond, Weight: 1.0}},
	}
	// SetNextPacketSize(0) should not override since GetPacketSize checks nextPacketSize > 0
	profile.SetNextPacketSize(0)
	got := profile.GetPacketSize()
	if got != 800 {
		t.Errorf("GetPacketSize() after SetNextPacketSize(0) = %d, want 800", got)
	}
}

func TestGetPacketSize_FallsBackToLast(t *testing.T) {
	// Edge case: random value > total cumulative weight, should fall back to last element
	profile := &TrafficProfile{
		// Total weight < 1.0 on purpose to test fallback
		PacketSizes: []PacketSizeDist{
			{Size: 100, Weight: 0.3},
			{Size: 200, Weight: 0.3},
		},
		Delays: []DelayDist{{Delay: 1 * time.Millisecond, Weight: 1.0}},
	}
	// Run many times - should always return either 100 or 200
	for i := 0; i < 100; i++ {
		s := profile.GetPacketSize()
		if s != 100 && s != 200 {
			t.Errorf("GetPacketSize() = %d, expected 100 or 200", s)
		}
	}
}

func TestGetDelay_FallsBackToLast(t *testing.T) {
	profile := &TrafficProfile{
		PacketSizes: []PacketSizeDist{{Size: 100, Weight: 1.0}},
		// Total weight < 1.0 to test fallback to last element
		Delays: []DelayDist{
			{Delay: 5 * time.Millisecond, Weight: 0.3},
			{Delay: 15 * time.Millisecond, Weight: 0.3},
		},
	}
	for i := 0; i < 100; i++ {
		d := profile.GetDelay()
		if d != 5*time.Millisecond && d != 15*time.Millisecond {
			t.Errorf("GetDelay() = %v, expected 5ms or 15ms", d)
		}
	}
}

func TestHTTPAPIProfile(t *testing.T) {
	profile := Profiles["mimic-http2-api"]
	if profile == nil {
		t.Fatal("mimic-http2-api profile not found")
	}
	size := profile.GetPacketSize()
	validSizes := []int{200, 500, 1000, 1500}
	found := false
	for _, s := range validSizes {
		if size == s {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("GetPacketSize() = %d, not in valid sizes for mimic-http2-api", size)
	}
}
