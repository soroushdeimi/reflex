package reflex_test

import (
	"testing"
	"time"

	"github.com/xtls/xray-core/proxy/reflex"
)

func TestTrafficProfileGetPacketSize(t *testing.T) {
	profile := reflex.YouTubeProfile

	// Test multiple calls to ensure distribution works
	sizes := make(map[int]int)
	for i := 0; i < 1000; i++ {
		size := profile.GetPacketSize()
		sizes[size]++
	}

	// Verify we get different sizes (distribution works)
	if len(sizes) < 2 {
		t.Fatal("expected multiple packet sizes from distribution")
	}

	// Verify sizes are from the profile
	validSizes := map[int]bool{1400: true, 1200: true, 1000: true, 800: true, 600: true, 400: true}
	for size := range sizes {
		if !validSizes[size] {
			t.Errorf("unexpected packet size: %d", size)
		}
	}
}

func TestTrafficProfileGetDelay(t *testing.T) {
	profile := reflex.ZoomProfile

	// Test multiple calls to ensure distribution works
	delays := make(map[time.Duration]int)
	for i := 0; i < 1000; i++ {
		delay := profile.GetDelay()
		delays[delay]++
	}

	// Verify we get different delays (distribution works)
	if len(delays) < 2 {
		t.Fatal("expected multiple delays from distribution")
	}

	// Verify delays are from the profile
	validDelays := map[time.Duration]bool{
		30 * time.Millisecond: true,
		40 * time.Millisecond: true,
		50 * time.Millisecond: true,
	}
	for delay := range delays {
		if !validDelays[delay] {
			t.Errorf("unexpected delay: %v", delay)
		}
	}
}

func TestTrafficProfileOverride(t *testing.T) {
	profile := reflex.HTTP2APIProfile

	// Set override
	overrideSize := 999
	profile.SetNextPacketSize(overrideSize)

	// Get packet size - should return override
	size := profile.GetPacketSize()
	if size != overrideSize {
		t.Fatalf("expected override size %d, got %d", overrideSize, size)
	}

	// Next call should use distribution again
	size2 := profile.GetPacketSize()
	if size2 == overrideSize {
		t.Fatal("override should be reset after use")
	}

	// Test delay override
	overrideDelay := 99 * time.Millisecond
	profile.SetNextDelay(overrideDelay)

	delay := profile.GetDelay()
	if delay != overrideDelay {
		t.Fatalf("expected override delay %v, got %v", overrideDelay, delay)
	}

	// Next call should use distribution again
	delay2 := profile.GetDelay()
	if delay2 == overrideDelay {
		t.Fatal("override should be reset after use")
	}
}

func TestGetProfile(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected *reflex.TrafficProfile
	}{
		{"youtube", "youtube", reflex.YouTubeProfile},
		{"zoom", "zoom", reflex.ZoomProfile},
		{"http2-api", "http2-api", reflex.HTTP2APIProfile},
		{"http2api", "http2api", reflex.HTTP2APIProfile},
		{"unknown", "unknown", nil},
		{"empty", "", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile := reflex.GetProfile(tt.input)
			if profile != tt.expected {
				if tt.expected == nil {
					t.Fatalf("expected nil for %s, got %v", tt.input, profile)
				}
				if profile == nil {
					t.Fatalf("expected profile for %s, got nil", tt.input)
				}
				if profile.Name != tt.expected.Name {
					t.Fatalf("expected profile %s, got %s", tt.expected.Name, profile.Name)
				}
			}
		})
	}
}

func TestCreateProfileFromCapture(t *testing.T) {
	packetSizes := []int{100, 200, 200, 300, 300, 300, 400}
	delays := []time.Duration{
		10 * time.Millisecond,
		20 * time.Millisecond,
		20 * time.Millisecond,
		30 * time.Millisecond,
	}

	profile := reflex.CreateProfileFromCapture(packetSizes, delays)

	if profile == nil {
		t.Fatal("expected profile, got nil")
	}

	if profile.Name != "Custom" {
		t.Fatalf("expected name 'Custom', got '%s'", profile.Name)
	}

	// Verify size distribution
	if len(profile.PacketSizes) == 0 {
		t.Fatal("expected packet size distribution")
	}

	// Verify delay distribution
	if len(profile.Delays) == 0 {
		t.Fatal("expected delay distribution")
	}

	// Verify weights sum to approximately 1.0
	sizeSum := 0.0
	for _, dist := range profile.PacketSizes {
		sizeSum += dist.Weight
	}
	if sizeSum < 0.99 || sizeSum > 1.01 {
		t.Errorf("size weights should sum to ~1.0, got %f", sizeSum)
	}

	delaySum := 0.0
	for _, dist := range profile.Delays {
		delaySum += dist.Weight
	}
	if delaySum < 0.99 || delaySum > 1.01 {
		t.Errorf("delay weights should sum to ~1.0, got %f", delaySum)
	}
}

func TestPredefinedProfiles(t *testing.T) {
	profiles := []*reflex.TrafficProfile{
		reflex.YouTubeProfile,
		reflex.ZoomProfile,
		reflex.HTTP2APIProfile,
	}

	for _, profile := range profiles {
		if profile == nil {
			t.Fatal("profile should not be nil")
		}

		if len(profile.PacketSizes) == 0 {
			t.Errorf("profile %s has no packet sizes", profile.Name)
		}

		if len(profile.Delays) == 0 {
			t.Errorf("profile %s has no delays", profile.Name)
		}

		// Verify weights sum to approximately 1.0
		sizeSum := 0.0
		for _, dist := range profile.PacketSizes {
			sizeSum += dist.Weight
		}
		if sizeSum < 0.99 || sizeSum > 1.01 {
			t.Errorf("profile %s: size weights should sum to ~1.0, got %f", profile.Name, sizeSum)
		}

		delaySum := 0.0
		for _, dist := range profile.Delays {
			delaySum += dist.Weight
		}
		if delaySum < 0.99 || delaySum > 1.01 {
			t.Errorf("profile %s: delay weights should sum to ~1.0, got %f", profile.Name, delaySum)
		}
	}
}
