package reflex

import (
	"math"
	"math/rand"
	"sort"
	"sync"
	"time"
)

// TrafficProfile defines a statistical profile for packet sizes and delays
// to mimic a specific type of traffic (e.g., YouTube, Zoom).
type TrafficProfile struct {
	Name        string
	PacketSizes []PacketSizeDist
	Delays      []DelayDist

	nextPacketSize int
	nextDelay      time.Duration
	mu             sync.Mutex
}

// PacketSizeDist represents a probability distribution for a specific packet size.
type PacketSizeDist struct {
	Size   int
	Weight float64
}

// DelayDist represents a probability distribution for a specific inter-packet delay.
type DelayDist struct {
	Delay  time.Duration
	Weight float64
}

var Profiles = map[string]*TrafficProfile{
	"youtube": {
		Name: "YouTube",
		PacketSizes: []PacketSizeDist{
			{Size: 1400, Weight: 0.35},
			{Size: 1200, Weight: 0.25},
			{Size: 1000, Weight: 0.20},
			{Size: 800, Weight: 0.10},
			{Size: 600, Weight: 0.05},
			{Size: 400, Weight: 0.05},
		},
		Delays: []DelayDist{
			{Delay: 8 * time.Millisecond, Weight: 0.30},
			{Delay: 12 * time.Millisecond, Weight: 0.25},
			{Delay: 16 * time.Millisecond, Weight: 0.20},
			{Delay: 20 * time.Millisecond, Weight: 0.15},
			{Delay: 30 * time.Millisecond, Weight: 0.10},
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
	"mimic-http2-api": {
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

func (p *TrafficProfile) GetPacketSize() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.nextPacketSize > 0 {
		size := p.nextPacketSize
		p.nextPacketSize = 0
		return size
	}

	r := rand.Float64()
	cumsum := 0.0
	for _, dist := range p.PacketSizes {
		cumsum += dist.Weight
		if r <= cumsum {
			return dist.Size
		}
	}
	return p.PacketSizes[len(p.PacketSizes)-1].Size
}

func (p *TrafficProfile) GetDelay() time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.nextDelay > 0 {
		delay := p.nextDelay
		p.nextDelay = 0
		return delay
	}

	r := rand.Float64()
	cumsum := 0.0
	for _, dist := range p.Delays {
		cumsum += dist.Weight
		if r <= cumsum {
			return dist.Delay
		}
	}
	return p.Delays[len(p.Delays)-1].Delay
}

func (p *TrafficProfile) SetNextPacketSize(size int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.nextPacketSize = size
}

func (p *TrafficProfile) SetNextDelay(delay time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.nextDelay = delay
}

// CreateProfileFromCapture generates a profile from raw observation data
func CreateProfileFromCapture(name string, packetSizes []int, delays []time.Duration) *TrafficProfile {
	return &TrafficProfile{
		Name:        name,
		PacketSizes: CalculateSizeDistribution(packetSizes),
		Delays:      CalculateDelayDistribution(delays),
	}
}

func CalculateSizeDistribution(values []int) []PacketSizeDist {
	freq := make(map[int]int)
	for _, v := range values {
		freq[v]++
	}

	total := len(values)
	dist := make([]PacketSizeDist, 0, len(freq))
	for size, count := range freq {
		dist = append(dist, PacketSizeDist{
			Size:   size,
			Weight: float64(count) / float64(total),
		})
	}

	sort.Slice(dist, func(i, j int) bool {
		return dist[i].Size < dist[j].Size
	})
	return dist
}

func CalculateDelayDistribution(values []time.Duration) []DelayDist {
	freq := make(map[time.Duration]int)
	for _, v := range values {
		freq[v]++
	}

	total := len(values)
	dist := make([]DelayDist, 0, len(freq))
	for delay, count := range freq {
		dist = append(dist, DelayDist{
			Delay:  delay,
			Weight: float64(count) / float64(total),
		})
	}

	sort.Slice(dist, func(i, j int) bool {
		return dist[i].Delay < dist[j].Delay
	})
	return dist
}

type KSResult struct {
	DStatistic float64
	PValue     float64 // Simplified P-value estimation
}

// KolmogorovSmirnovTest compares two samples to see if they come from the same distribution
func KolmogorovSmirnovTest(sample1, sample2 []float64) KSResult {
	if len(sample1) == 0 || len(sample2) == 0 {
		return KSResult{DStatistic: 1.0, PValue: 0}
	}

	sort.Float64s(sample1)
	sort.Float64s(sample2)

	var maxD float64
	n1 := float64(len(sample1))
	n2 := float64(len(sample2))

	i, j := 0, 0
	for i < len(sample1) && j < len(sample2) {
		val1 := sample1[i]
		val2 := sample2[j]

		var curVal float64
		if val1 <= val2 {
			curVal = val1
		} else {
			curVal = val2
		}

		// Calculate ECDF for both samples at curVal
		for i < len(sample1) && sample1[i] <= curVal {
			i++
		}
		for j < len(sample2) && sample2[j] <= curVal {
			j++
		}

		ecdf1 := float64(i) / n1
		ecdf2 := float64(j) / n2

		diff := math.Abs(ecdf1 - ecdf2)
		if diff > maxD {
			maxD = diff
		}
	}

	// Simplified p-value estimation for the KS test
	en := math.Sqrt((n1 * n2) / (n1 + n2))
	lambda := maxD * en
	pValue := 2 * math.Exp(-2*lambda*lambda)
	if pValue > 1.0 {
		pValue = 1.0
	}

	return KSResult{
		DStatistic: maxD,
		PValue:     pValue,
	}
}
