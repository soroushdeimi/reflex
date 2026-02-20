package reflex

import (
	"fmt"
	"math"
	"sort"
	"sync"
	"time"
)

// TrafficStats collects traffic statistics
type TrafficStats struct {
	mu sync.RWMutex

	// Packet size statistics
	PacketSizes []int
	SizeHist    map[int]int // Size -> Count

	// Delay statistics
	Delays    []time.Duration
	DelayHist map[int]int // Delay (ms) -> Count

	// General stats
	TotalPackets int64
	TotalBytes   int64
	StartTime    time.Time
	EndTime      time.Time
}

// NewTrafficStats creates new stats collector
func NewTrafficStats() *TrafficStats {
	return &TrafficStats{
		PacketSizes: make([]int, 0),
		SizeHist:    make(map[int]int),
		Delays:      make([]time.Duration, 0),
		DelayHist:   make(map[int]int),
		StartTime:   time.Now(),
	}
}

// RecordPacket records a packet
func (ts *TrafficStats) RecordPacket(size int, delay time.Duration) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	ts.PacketSizes = append(ts.PacketSizes, size)
	ts.SizeHist[size]++

	if delay > 0 {
		ts.Delays = append(ts.Delays, delay)
		delayMs := int(delay.Milliseconds())
		ts.DelayHist[delayMs]++
	}

	ts.TotalPackets++
	ts.TotalBytes += int64(size)
}

// Finish finalizes statistics
func (ts *TrafficStats) Finish() {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.EndTime = time.Now()
}

// GetSizeStats returns size statistics
func (ts *TrafficStats) GetSizeStats() SizeStatistics {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	if len(ts.PacketSizes) == 0 {
		return SizeStatistics{}
	}

	sizes := make([]int, len(ts.PacketSizes))
	copy(sizes, ts.PacketSizes)
	sort.Ints(sizes)

	return SizeStatistics{
		Count:  len(sizes),
		Min:    sizes[0],
		Max:    sizes[len(sizes)-1],
		Mean:   mean(sizes),
		Median: sizes[len(sizes)/2],
		Stddev: stddev(sizes),
		P95:    percentile(sizes, 0.95),
		P99:    percentile(sizes, 0.99),
	}
}

// GetDelayStats returns delay statistics
func (ts *TrafficStats) GetDelayStats() DelayStatistics {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	if len(ts.Delays) == 0 {
		return DelayStatistics{}
	}

	delays := make([]time.Duration, len(ts.Delays))
	copy(delays, ts.Delays)
	sort.Slice(delays, func(i, j int) bool {
		return delays[i] < delays[j]
	})

	return DelayStatistics{
		Count:  len(delays),
		Min:    delays[0],
		Max:    delays[len(delays)-1],
		Mean:   meanDuration(delays),
		Median: delays[len(delays)/2],
		Stddev: stddevDuration(delays),
		P95:    percentileDuration(delays, 0.95),
		P99:    percentileDuration(delays, 0.99),
	}
}

// SizeStatistics holds size statistics
type SizeStatistics struct {
	Count  int
	Min    int
	Max    int
	Mean   float64
	Median int
	Stddev float64
	P95    int
	P99    int
}

// DelayStatistics holds delay statistics
type DelayStatistics struct {
	Count  int
	Min    time.Duration
	Max    time.Duration
	Mean   time.Duration
	Median time.Duration
	Stddev time.Duration
	P95    time.Duration
	P99    time.Duration
}

// String returns string representation
func (ss SizeStatistics) String() string {
	return fmt.Sprintf(
		"PacketSizes: Count=%d, Min=%d, Max=%d, Mean=%.2f, Median=%d, Stddev=%.2f, P95=%d, P99=%d",
		ss.Count, ss.Min, ss.Max, ss.Mean, ss.Median, ss.Stddev, ss.P95, ss.P99,
	)
}

// String returns string representation
func (ds DelayStatistics) String() string {
	return fmt.Sprintf(
		"Delays: Count=%d, Min=%v, Max=%v, Mean=%v, Median=%v, Stddev=%v, P95=%v, P99=%v",
		ds.Count, ds.Min, ds.Max, ds.Mean, ds.Median, ds.Stddev, ds.P95, ds.P99,
	)
}

// Helper functions

func mean(values []int) float64 {
	if len(values) == 0 {
		return 0
	}
	sum := 0
	for _, v := range values {
		sum += v
	}
	return float64(sum) / float64(len(values))
}

func stddev(values []int) float64 {
	if len(values) == 0 {
		return 0
	}
	m := mean(values)
	sumSq := 0.0
	for _, v := range values {
		diff := float64(v) - m
		sumSq += diff * diff
	}
	return math.Sqrt(sumSq / float64(len(values)))
}

func percentile(values []int, p float64) int {
	if len(values) == 0 {
		return 0
	}
	index := int(float64(len(values)) * p)
	if index >= len(values) {
		index = len(values) - 1
	}
	return values[index]
}

func meanDuration(values []time.Duration) time.Duration {
	if len(values) == 0 {
		return 0
	}
	sum := int64(0)
	for _, v := range values {
		sum += int64(v)
	}
	return time.Duration(sum / int64(len(values)))
}

func stddevDuration(values []time.Duration) time.Duration {
	if len(values) == 0 {
		return 0
	}
	m := meanDuration(values)
	sumSq := int64(0)
	for _, v := range values {
		diff := int64(v) - int64(m)
		sumSq += diff * diff
	}
	variance := float64(sumSq) / float64(len(values))
	return time.Duration(math.Sqrt(variance))
}

func percentileDuration(values []time.Duration, p float64) time.Duration {
	if len(values) == 0 {
		return 0
	}
	index := int(float64(len(values)) * p)
	if index >= len(values) {
		index = len(values) - 1
	}
	return values[index]
}

// KolmogorovSmirnovTest performs KS test between two distributions
// Returns the KS statistic (max difference between ECDFs)
func KolmogorovSmirnovTest(sample1, sample2 []int) float64 {
	if len(sample1) == 0 || len(sample2) == 0 {
		return 1.0
	}

	// Sort both samples
	s1 := make([]int, len(sample1))
	s2 := make([]int, len(sample2))
	copy(s1, sample1)
	copy(s2, sample2)
	sort.Ints(s1)
	sort.Ints(s2)

	n1 := float64(len(s1))
	n2 := float64(len(s2))

	maxDiff := 0.0
	i1, i2 := 0, 0

	// Iterate through both sorted arrays
	for i1 < len(s1) || i2 < len(s2) {
		var currentValue int

		// Determine current value to evaluate
		if i1 < len(s1) && (i2 >= len(s2) || s1[i1] <= s2[i2]) {
			currentValue = s1[i1]
		} else if i2 < len(s2) {
			currentValue = s2[i2]
		} else {
			break
		}

		// Advance i1 to include all values <= currentValue
		for i1 < len(s1) && s1[i1] <= currentValue {
			i1++
		}

		// Advance i2 to include all values <= currentValue
		for i2 < len(s2) && s2[i2] <= currentValue {
			i2++
		}

		// Calculate empirical CDFs at currentValue
		cdf1 := float64(i1) / n1
		cdf2 := float64(i2) / n2

		// Update max difference
		diff := math.Abs(cdf1 - cdf2)
		if diff > maxDiff {
			maxDiff = diff
		}
	}

	return maxDiff
}
