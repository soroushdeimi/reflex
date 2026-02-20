package reflex

import (
	"math"
	"testing"
	"time"
)

func TestTrafficStatsRecording(t *testing.T) {
	ts := NewTrafficStats()

	ts.RecordPacket(1400, 10*time.Millisecond)
	ts.RecordPacket(600, 20*time.Millisecond)
	ts.Finish()

	if ts.TotalPackets != 2 {
		t.Errorf("expected 2 packets, got %d", ts.TotalPackets)
	}
	if ts.TotalBytes != 2000 {
		t.Errorf("expected 2000 bytes, got %d", ts.TotalBytes)
	}
	if ts.EndTime.Before(ts.StartTime) {
		t.Error("finish time invalid")
	}
}

func TestSizeStatistics(t *testing.T) {
	ts := NewTrafficStats()
	sizes := []int{100, 200, 300, 400, 500}
	for _, s := range sizes {
		ts.RecordPacket(s, 0)
	}

	stats := ts.GetSizeStats()
	if stats.Min != 100 || stats.Max != 500 {
		t.Errorf("min/max error: %d/%d", stats.Min, stats.Max)
	}
	if stats.Mean != 300 {
		t.Errorf("mean error: %f", stats.Mean)
	}
	if stats.Median != 300 {
		t.Errorf("median error: %d", stats.Median)
	}
}

func TestDelayStatistics(t *testing.T) {
	ts := NewTrafficStats()
	delays := []time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 30 * time.Millisecond}
	for _, d := range delays {
		ts.RecordPacket(100, d)
	}

	stats := ts.GetDelayStats()
	if stats.Min != 10*time.Millisecond || stats.Max != 30*time.Millisecond {
		t.Errorf("delay min/max error")
	}
	if stats.Mean != 20*time.Millisecond {
		t.Errorf("delay mean error: %v", stats.Mean)
	}
}

func TestKolmogorovSmirnovTest(t *testing.T) {
	// Identical distributions
	s1 := []int{100, 200, 300}
	s2 := []int{100, 200, 300}
	res := KolmogorovSmirnovTest(s1, s2)
	if res > 0.0001 {
		t.Errorf("identical distributions should have 0 KS stat, got %f", res)
	}

	// Different distributions
	s3 := []int{10, 20, 30}
	s4 := []int{1000, 2000, 3000}
	resDiff := KolmogorovSmirnovTest(s3, s4)
	if resDiff < 0.9 {
		t.Errorf("different distributions should have high KS stat, got %f", resDiff)
	}
}

func TestEmptyStats(t *testing.T) {
	ts := NewTrafficStats()
	sStats := ts.GetSizeStats()
	if sStats.Count != 0 {
		t.Error("count should be 0")
	}
}

func TestMathHelpers(t *testing.T) {
	vals := []int{1, 2, 3, 4, 5}
	m := mean(vals)
	if m != 3.0 {
		t.Errorf("mean failed: %f", m)
	}

	sd := stddev(vals)
	if math.IsNaN(sd) || sd == 0 {
		t.Error("stddev failed")
	}

	p := percentile(vals, 0.5)
	if p != 3 {
		t.Errorf("percentile failed: %d", p)
	}
}
