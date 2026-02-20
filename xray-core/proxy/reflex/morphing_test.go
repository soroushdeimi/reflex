package reflex

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"
)

func generateHistogram(data []float64) map[int]int {
	hist := make(map[int]int)
	for _, v := range data {
		hist[int(v)]++
	}
	return hist
}

func formatHistogram(hist map[int]int, total int) string {
	keys := make([]int, 0, len(hist))
	for k := range hist {
		keys = append(keys, k)
	}
	sort.Ints(keys)

	var sb strings.Builder
	for _, k := range keys {
		count := hist[k]
		percent := float64(count) / float64(total) * 100
		bar := strings.Repeat("█", int(percent/2))
		sb.WriteString(fmt.Sprintf("%4d: %s %.1f%%\n", k, bar, percent))
	}
	return sb.String()
}

func TestGenerateMorphingReport(t *testing.T) {
	profileName := "youtube"
	profile := Profiles[profileName]
	iterations := 2000

	// 1. Generate Morphed Traffic
	morphedSample := make([]float64, iterations)
	for i := 0; i < iterations; i++ {
		morphedSample[i] = float64(profile.GetPacketSize())
	}

	// 2. Generate Reference (Ideal) Traffic
	idealSample := make([]float64, iterations)
	for i := 0; i < iterations; i++ {
		r := float64(i) / float64(iterations)
		cumsum := 0.0
		for _, dist := range profile.PacketSizes {
			cumsum += dist.Weight
			if r <= cumsum {
				idealSample[i] = float64(dist.Size)
				break
			}
		}
	}

	// 3. Analysis
	result := KolmogorovSmirnovTest(morphedSample, idealSample)
	morphedHist := generateHistogram(morphedSample)
	idealHist := generateHistogram(idealSample)

	// 4. Create Markdown Report
	report := fmt.Sprintf(`# Traffic Morphing Statistical Evidence
## Profile: %s
- **Iterations**: %d
- **KS-Statistic**: %f
- **P-Value**: %f
- **Verdict**: %s

### Morphing Distribution (Actual)
%s
`+"```"+`
%s
`+"```"+`

### Target Distribution (Real/Ideal)
%s
`+"```"+`
%s
`+"```"+`

---
*Generated: %s*
`,
		profile.Name, iterations, result.DStatistic, result.PValue,
		func() string {
			if result.PValue > 0.05 {
				return "✅ Success (Distributions are indistinguishable)"
			}
			return "❌ Failed (Distributions are statistically different)"
		}(),
		profile.Name, formatHistogram(morphedHist, iterations),
		profile.Name, formatHistogram(idealHist, iterations),
		time.Now().Format(time.RFC1123),
	)

	err := os.WriteFile("morphing_evidence.md", []byte(report), 0644)
	if err != nil {
		t.Fatalf("Failed to write report: %v", err)
	}
	t.Log("Statistical evidence report generated: morphing_evidence.md")
}

func TestTrafficProfile_GetPacketSize(t *testing.T) {
	profile := Profiles["youtube"]
	counts := make(map[int]int)
	iterations := 10000

	for i := 0; i < iterations; i++ {
		size := profile.GetPacketSize()
		counts[size]++
	}

	// Check if sizes are within the defined profile
	for size, count := range counts {
		found := false
		for _, dist := range profile.PacketSizes {
			if dist.Size == size {
				found = true
				// Roughly check weight (0.35 for 1400)
				expected := dist.Weight * float64(iterations)
				if float64(count) < expected*0.8 || float64(count) > expected*1.2 {
					t.Logf("Size %d distribution: got %d, expected ~%f", size, count, expected)
				}
				break
			}
		}
		if !found {
			t.Errorf("Unexpected size %d found in distribution", size)
		}
	}
}

func TestMorphingStatistical(t *testing.T) {
	profile := Profiles["youtube"]
	iterations := 1000

	// 1. Generate "morphed" traffic
	morphedSample := make([]float64, iterations)
	for i := 0; i < iterations; i++ {
		morphedSample[i] = float64(profile.GetPacketSize())
	}

	// 2. Ideal sample based on the same distribution
	idealSample := make([]float64, iterations)
	for i := 0; i < iterations; i++ {
		r := float64(i) / float64(iterations)
		cumsum := 0.0
		for _, dist := range profile.PacketSizes {
			cumsum += dist.Weight
			if r <= cumsum {
				idealSample[i] = float64(dist.Size)
				break
			}
		}
	}

	// 3. Perform KS Test
	result := KolmogorovSmirnovTest(morphedSample, idealSample)
	t.Logf("KS Statistic: %f, P-Value: %f", result.DStatistic, result.PValue)

	// In KS test, a high p-value (e.g. > 0.05) means we cannot reject the null hypothesis
	// that they come from the same distribution.
	if result.PValue < 0.01 { // Using a conservative alpha for randomized output
		t.Errorf("Morphing failed statistical test: p-value %f is too low", result.PValue)
	}
}

func TestProfileFromCapture(t *testing.T) {
	// Simulate raw captured sizes from an external tool
	capturedSizes := []int{1400, 1400, 1400, 800, 600, 1400, 1200, 1000, 1400, 1400}
	
	profile := CreateProfileFromCapture("captured", capturedSizes, []time.Duration{10 * time.Millisecond})
	
	if profile.Name != "captured" {
		t.Errorf("Expected name 'captured', got %s", profile.Name)
	}
	
	// Check if 1400 has the highest weight (6/10 = 0.6)
	found := false
	for _, dist := range profile.PacketSizes {
		if dist.Size == 1400 {
			if dist.Weight != 0.6 {
				t.Errorf("Expected weight 0.6 for size 1400, got %f", dist.Weight)
			}
			found = true
		}
	}
	if !found {
		t.Error("Size 1400 not found in captured distribution")
	}
}
