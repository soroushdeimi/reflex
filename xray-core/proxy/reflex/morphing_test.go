package reflex

import (
	"bytes"
	"testing"
	"time"
)

func TestMorphingProfile(t *testing.T) {
	profile := YouTubeProfile

	// Test packet size sampling
	for i := 0; i < 100; i++ {
		size := profile.GetPacketSize()
		if size <= 0 {
			t.Errorf("invalid packet size: %d", size)
		}
	}

	// Test delay sampling
	for i := 0; i < 100; i++ {
		delay := profile.GetDelay()
		if delay <= 0 {
			t.Errorf("invalid delay: %v", delay)
		}
	}
}

func TestMorphingWriter(t *testing.T) {
	buf := &bytes.Buffer{}
	writer := NewMorphingWriter(buf, YouTubeProfile)

	data := []byte("Hello, World!")
	n, err := writer.WriteWithMorphing(data)

	if err != nil {
		t.Errorf("failed to write: %v", err)
	}

	if n <= 0 {
		t.Errorf("invalid write count: %d", n)
	}

	// Morphed data should be >= original
	if buf.Len() < len(data) {
		t.Errorf("morphed size too small: %d < %d", buf.Len(), len(data))
	}
}

func TestTrafficStats(t *testing.T) {
	stats := NewTrafficStats()

	// Record some packets
	sizes := []int{1400, 1200, 1000, 800, 600}
	delays := []time.Duration{
		10 * time.Millisecond,
		15 * time.Millisecond,
		20 * time.Millisecond,
	}

	for _, size := range sizes {
		for _, delay := range delays {
			stats.RecordPacket(size, delay)
		}
	}

	stats.Finish()

	// Check stats
	sizeStats := stats.GetSizeStats()
	if sizeStats.Count != len(sizes)*len(delays) {
		t.Errorf("wrong packet count: %d", sizeStats.Count)
	}

	if sizeStats.Min != 600 || sizeStats.Max != 1400 {
		t.Errorf("wrong min/max: %d/%d", sizeStats.Min, sizeStats.Max)
	}

	t.Logf("Size stats: %v", sizeStats)
	t.Logf("Delay stats: %v", stats.GetDelayStats())
}

func TestProfileCreationFromSamples(t *testing.T) {
	sizes := []int{1000, 1100, 1000, 1200, 1000, 900, 1000}
	delays := []time.Duration{
		10 * time.Millisecond,
		15 * time.Millisecond,
		10 * time.Millisecond,
	}

	profile := CreateProfileFromSamples(sizes, delays)

	if profile == nil {
		t.Fatal("failed to create profile")
	}

	if profile.Name != "Custom" {
		t.Errorf("wrong profile name: %s", profile.Name)
	}

	size := profile.GetPacketSize()
	if size <= 0 {
		t.Errorf("invalid sample size: %d", size)
	}
}

func TestKSTest(t *testing.T) {
	// Test 1: Identical distributions should have KS stat = 0
	sample := []int{1000, 1100, 1200, 1300, 1400}
	stat := KolmogorovSmirnovTest(sample, sample)

	t.Logf("KS stat for identical samples: %.6f", stat)

	// For identical samples, KS stat should be exactly 0
	if stat != 0.0 {
		t.Errorf("KS stat for identical samples should be 0.0, got: %.6f", stat)
	}

	// Test 2: Similar distributions (small difference)
	sample1 := []int{1000, 1100, 1200, 1300, 1400}
	sample2 := []int{1000, 1050, 1200, 1350, 1400}
	stat = KolmogorovSmirnovTest(sample1, sample2)

	t.Logf("KS stat for similar samples: %.6f", stat)

	if stat > 0.5 {
		t.Errorf("KS stat for similar samples too high: %.6f", stat)
	}

	// Test 3: Very different distributions should have high KS stat
	sample1 = []int{100, 200, 300, 400, 500}
	sample2 = []int{1000, 1100, 1200, 1300, 1400}
	stat = KolmogorovSmirnovTest(sample1, sample2)

	t.Logf("KS stat for different samples: %.6f", stat)

	if stat < 0.8 {
		t.Errorf("KS stat for different samples too low: %.6f (expected > 0.8)", stat)
	}

	// Test 4: Overlapping distributions
	sample1 = []int{500, 600, 700, 800, 900}
	sample2 = []int{700, 800, 900, 1000, 1100}
	stat = KolmogorovSmirnovTest(sample1, sample2)

	t.Logf("KS stat for overlapping samples: %.6f", stat)

	if stat < 0.1 || stat > 0.7 {
		t.Errorf("KS stat for overlapping samples out of expected range: %.6f", stat)
	}

	// Test 5: Empty samples edge case
	emptySample := []int{}
	stat = KolmogorovSmirnovTest(emptySample, sample)
	if stat != 1.0 {
		t.Errorf("KS stat for empty sample should be 1.0, got: %.6f", stat)
	}

	// Test 6: Single element samples
	single1 := []int{100}
	single2 := []int{100}
	stat = KolmogorovSmirnovTest(single1, single2)
	t.Logf("KS stat for identical single elements: %.6f", stat)
	if stat != 0.0 {
		t.Errorf("KS stat for identical single elements should be 0.0, got: %.6f", stat)
	}

	// Test 7: Different single elements
	single1 = []int{100}
	single2 = []int{200}
	stat = KolmogorovSmirnovTest(single1, single2)
	t.Logf("KS stat for different single elements: %.6f", stat)
	if stat != 1.0 {
		t.Errorf("KS stat for different single elements should be 1.0, got: %.6f", stat)
	}
}

func TestKSTestExtended(t *testing.T) {
	// Test with larger datasets
	large1 := make([]int, 1000)
	large2 := make([]int, 1000)
	for i := 0; i < 1000; i++ {
		large1[i] = i
		large2[i] = i
	}

	stat := KolmogorovSmirnovTest(large1, large2)
	t.Logf("KS stat for large identical samples: %.6f", stat)
	if stat != 0.0 {
		t.Errorf("KS stat for large identical samples should be 0.0, got: %.6f", stat)
	}

	// Test with shifted distribution (Shift by 500 out of 1000)
	for i := 0; i < 1000; i++ {
		large2[i] = i + 500 // Significant shift
	}
	stat = KolmogorovSmirnovTest(large1, large2)
	t.Logf("KS stat for shifted distribution: %.6f", stat)

	// With 50% shift, KS stat should be 0.5
	if stat < 0.4 {
		t.Errorf("KS stat for significantly shifted distribution too low: %.6f", stat)
	}
}
