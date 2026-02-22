package reflex

import (
	"math/rand"
	"sync"
	"time"
)

var (
	rng   = rand.New(rand.NewSource(time.Now().UnixNano()))
	rngMu sync.Mutex
)

// TrafficProfile controls traffic morphing (packet size & timing distributions).
//
// NOTE: This is a simplified implementation intended for the assignment.
type TrafficProfile struct {
	Name string

	PacketSizes []PacketSizeDist
	Delays      []DelayDist

	nextPacketSize int
	nextDelay      time.Duration
	mu             sync.Mutex
}

// PacketSizeDist represents a weighted packet size.
type PacketSizeDist struct {
	Size   int
	Weight float64
}

// DelayDist represents a weighted delay.
type DelayDist struct {
	Delay  time.Duration
	Weight float64
}

// Profiles contains built-in profiles.
var Profiles = map[string]*TrafficProfile{
	"youtube": {
		Name: "YouTube",
		PacketSizes: []PacketSizeDist{
			{Size: 1400, Weight: 0.4},
			{Size: 1200, Weight: 0.3},
			{Size: 1000, Weight: 0.2},
			{Size: 800, Weight: 0.1},
		},
		Delays: []DelayDist{
			{Delay: 10 * time.Millisecond, Weight: 0.5},
			{Delay: 20 * time.Millisecond, Weight: 0.3},
			{Delay: 30 * time.Millisecond, Weight: 0.2},
		},
	},
	"zoom": {
		Name: "Zoom",
		PacketSizes: []PacketSizeDist{
			{Size: 500, Weight: 0.3},
			{Size: 600, Weight: 0.4},
			{Size: 700, Weight: 0.3},
		},
		Delays: []DelayDist{
			{Delay: 30 * time.Millisecond, Weight: 0.4},
			{Delay: 40 * time.Millisecond, Weight: 0.4},
			{Delay: 50 * time.Millisecond, Weight: 0.2},
		},
	},
	"http2-api": {
		Name: "HTTP/2 API",
		PacketSizes: []PacketSizeDist{
			{Size: 200, Weight: 0.2},
			{Size: 500, Weight: 0.3},
			{Size: 1000, Weight: 0.3},
			{Size: 1500, Weight: 0.2},
		},
		Delays: []DelayDist{
			{Delay: 5 * time.Millisecond, Weight: 0.3},
			{Delay: 10 * time.Millisecond, Weight: 0.4},
			{Delay: 15 * time.Millisecond, Weight: 0.3},
		},
	},
}

// CloneProfile returns a deep copy of a named profile.
//
// Profiles are stateful (they keep one-shot overrides), so callers should not
// share the global instances between connections.
func CloneProfile(name string) *TrafficProfile {
	p, ok := Profiles[name]
	if !ok || p == nil {
		return nil
	}
	// IMPORTANT: do not copy sync.Mutex; create a fresh profile instance.
	cp := &TrafficProfile{
		Name:        p.Name,
		PacketSizes: append([]PacketSizeDist(nil), p.PacketSizes...),
		Delays:      append([]DelayDist(nil), p.Delays...),
	}
	return cp
}

// GetPacketSize chooses the next packet size based on distribution or a one-shot override.
func (p *TrafficProfile) GetPacketSize() int {
	if p == nil {
		// No morphing.
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.nextPacketSize > 0 {
		sz := p.nextPacketSize
		p.nextPacketSize = 0
		return sz
	}
	if len(p.PacketSizes) == 0 {
		return 0
	}
	rngMu.Lock()
	r := rng.Float64()
	rngMu.Unlock()
	c := 0.0
	for _, d := range p.PacketSizes {
		c += d.Weight
		if r <= c {
			return d.Size
		}
	}
	return p.PacketSizes[len(p.PacketSizes)-1].Size
}

// GetDelay chooses the next delay based on distribution or a one-shot override.
func (p *TrafficProfile) GetDelay() time.Duration {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.nextDelay > 0 {
		d := p.nextDelay
		p.nextDelay = 0
		return d
	}
	if len(p.Delays) == 0 {
		return 0
	}
	rngMu.Lock()
	r := rng.Float64()
	rngMu.Unlock()
	c := 0.0
	for _, d := range p.Delays {
		c += d.Weight
		if r <= c {
			return d.Delay
		}
	}
	return p.Delays[len(p.Delays)-1].Delay
}

// SetNextPacketSize overrides the next packet size once.
func (p *TrafficProfile) SetNextPacketSize(size int) {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.nextPacketSize = size
	p.mu.Unlock()
}

// SetNextDelay overrides the next delay once.
func (p *TrafficProfile) SetNextDelay(delay time.Duration) {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.nextDelay = delay
	p.mu.Unlock()
}
