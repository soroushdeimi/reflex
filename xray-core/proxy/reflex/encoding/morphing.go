package encoding

import (
	"math/rand"
	"sync"
	"time"
)

// TrafficProfile defines traffic morphing patterns
// It simulates packet sizes and delays of different protocols
type TrafficProfile struct {
	Name        string
	PacketSizes []PacketSizePattern // Packet size distribution
	Delays      []DelayPattern      // Delay distribution
	mu          sync.Mutex
}

// PacketSizePattern defines a packet size with its probability
type PacketSizePattern struct {
	Size   int     // Packet size in bytes
	Weight float64 // Probability weight (0.0 to 1.0)
}

// DelayPattern defines a delay with its probability
type DelayPattern struct {
	Delay  time.Duration
	Weight float64
}

// Pre-defined traffic profiles based on common protocols
var (
	// YouTubeProfile mimics YouTube video streaming traffic
	YouTubeProfile = &TrafficProfile{
		Name: "YouTube",
		PacketSizes: []PacketSizePattern{
			{Size: 1400, Weight: 0.4}, // 40% chance - MTU size packets
			{Size: 1200, Weight: 0.3}, // 30% chance
			{Size: 1000, Weight: 0.2}, // 20% chance
			{Size: 800, Weight: 0.1},  // 10% chance
		},
		Delays: []DelayPattern{
			{Delay: 10 * time.Millisecond, Weight: 0.5},
			{Delay: 20 * time.Millisecond, Weight: 0.3},
			{Delay: 30 * time.Millisecond, Weight: 0.2},
		},
	}

	// ZoomProfile mimics Zoom video call traffic
	ZoomProfile = &TrafficProfile{
		Name: "Zoom",
		PacketSizes: []PacketSizePattern{
			{Size: 500, Weight: 0.3},
			{Size: 600, Weight: 0.4},
			{Size: 700, Weight: 0.3},
		},
		Delays: []DelayPattern{
			{Delay: 30 * time.Millisecond, Weight: 0.4},
			{Delay: 40 * time.Millisecond, Weight: 0.4},
			{Delay: 50 * time.Millisecond, Weight: 0.2},
		},
	}

	// HTTP2APIProfile mimics HTTP/2 REST API traffic
	HTTP2APIProfile = &TrafficProfile{
		Name: "HTTP/2 API",
		PacketSizes: []PacketSizePattern{
			{Size: 200, Weight: 0.2},
			{Size: 500, Weight: 0.3},
			{Size: 1000, Weight: 0.3},
			{Size: 1500, Weight: 0.2},
		},
		Delays: []DelayPattern{
			{Delay: 5 * time.Millisecond, Weight: 0.3},
			{Delay: 10 * time.Millisecond, Weight: 0.4},
			{Delay: 15 * time.Millisecond, Weight: 0.3},
		},
	}
)

// GetPacketSize returns a packet size based on the distribution
func (p *TrafficProfile) GetPacketSize() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Use weighted random selection
	r := rand.Float64()
	cumulative := 0.0

	for _, pattern := range p.PacketSizes {
		cumulative += pattern.Weight
		if r <= cumulative {
			return pattern.Size
		}
	}

	// Fallback to last size
	return p.PacketSizes[len(p.PacketSizes)-1].Size
}

// GetDelay returns a delay based on the distribution
func (p *TrafficProfile) GetDelay() time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Use weighted random selection
	r := rand.Float64()
	cumulative := 0.0

	for _, pattern := range p.Delays {
		cumulative += pattern.Weight
		if r <= cumulative {
			return pattern.Delay
		}
	}

	// Fallback to last delay
	return p.Delays[len(p.Delays)-1].Delay
}

// AddPadding adds random padding to reach target size
func AddPadding(data []byte, targetSize int) []byte {
	if len(data) >= targetSize {
		// If data is larger, truncate or split (caller should handle splitting)
		return data[:targetSize]
	}

	// Create padded data
	padded := make([]byte, targetSize)
	copy(padded, data)

	// Fill remaining space with random padding
	if targetSize > len(data) {
		rand.Read(padded[len(data):])
	}

	return padded
}

// GetProfileByName returns a profile by its name
// If name is empty or not found, defaults to HTTP/2 API profile
func GetProfileByName(name string) *TrafficProfile {
	switch name {
	case "youtube":
		return YouTubeProfile
	case "zoom":
		return ZoomProfile
	case "http2-api":
		return HTTP2APIProfile
	case "", "default":
		// Default to HTTP/2 API (most universal for web browsing)
		return HTTP2APIProfile
	default:
		// Unknown profile name: default to HTTP/2 API
		return HTTP2APIProfile
	}
}

// MorphingConfig holds morphing configuration
type MorphingConfig struct {
	Enabled bool
	Profile *TrafficProfile
}

// NewMorphingConfig creates a new morphing configuration
// If profileName is empty, defaults to HTTP/2 API profile
func NewMorphingConfig(enabled bool, profileName string) *MorphingConfig {
	config := &MorphingConfig{
		Enabled: enabled,
	}

	if enabled {
		// Always get a profile (defaults to HTTP/2 API if empty or not found)
		config.Profile = GetProfileByName(profileName)
	}

	return config
}

// GetDefaultProfile returns the default HTTP/2 API profile
// Use this when no user policy is specified
func GetDefaultProfile() *TrafficProfile {
	return HTTP2APIProfile
}
