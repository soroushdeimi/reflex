package reflex

import (
	"testing"
	"time"
)

func TestTrafficProfileSampling(t *testing.T) {
	// Test name and precomputation
	profile := YouTubeProfile
	if profile.Name != "YouTube" {
		t.Error("incorrect profile name")
	}

	// Test GetPacketSize sampling
	size := profile.GetPacketSize()
	validSize := false
	for _, s := range profile.PacketSizes {
		if size == s.Size {
			validSize = true
			break
		}
	}
	if !validSize {
		t.Errorf("sampled size %d not in distribution", size)
	}

	// Test GetDelay sampling
	delay := profile.GetDelay()
	if delay <= 0 {
		t.Error("sampled delay must be positive")
	}
}

func TestProfileOverrides(t *testing.T) {
	profile := NewTrafficProfile("Test",
		[]PacketSizeDist{{Size: 100, Weight: 1.0}},
		[]DelayDist{{Delay: time.Second, Weight: 1.0}},
	)

	// Test size override
	expectedSize := 500
	profile.SetNextSize(expectedSize)
	if s := profile.GetPacketSize(); s != expectedSize {
		t.Errorf("expected overridden size %d, got %d", expectedSize, s)
	}
	// Verify it resets after one use
	if s := profile.GetPacketSize(); s == expectedSize {
		t.Error("override should reset after use")
	}

	// Test delay override
	expectedDelay := 5 * time.Millisecond
	profile.SetNextDelay(expectedDelay)
	if d := profile.GetDelay(); d != expectedDelay {
		t.Errorf("expected overridden delay %v, got %v", expectedDelay, d)
	}
}

func TestGetProfileByName(t *testing.T) {
	cases := []struct {
		input string
		name  string
	}{
		{"youtube", "YouTube"},
		{"zoom", "Zoom"},
		{"http2-api", "HTTP2-API"},
		{"unknown", "Generic"},
	}

	for _, c := range cases {
		p := GetProfileByName(c.input)
		if p.Name != c.name {
			t.Errorf("input %s: expected %s, got %s", c.input, c.name, p.Name)
		}
	}
}

func TestCreateProfileFromSamples(t *testing.T) {
	sizes := []int{100, 100, 200} // 100 has 0.66 weight, 200 has 0.33
	delays := []time.Duration{time.Second, time.Second}

	p := CreateProfileFromSamples(sizes, delays)

	if p.Name != "Custom" {
		t.Error("expected name Custom")
	}

	if len(p.PacketSizes) != 2 {
		t.Errorf("expected 2 size distributions, got %d", len(p.PacketSizes))
	}

	// Verify weights
	expectedWeight := 2.0 / 3.0
	if p.PacketSizes[0].Weight < expectedWeight-0.01 || p.PacketSizes[0].Weight > expectedWeight+0.01 {
		t.Errorf("incorrect weight calculation: %f", p.PacketSizes[0].Weight)
	}
}
