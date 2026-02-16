package inbound

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
)

func TestAuthenticateUserUsesConstantTimeCompare(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(".", "inbound.go"))
	if err != nil {
		t.Fatalf("read inbound.go: %v", err)
	}
	if !strings.Contains(string(src), "subtle.ConstantTimeCompare") {
		t.Fatal("authenticateUser should use subtle.ConstantTimeCompare to reduce timing leaks")
	}
}

func TestAuthenticateUserTimingMismatchPosition(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test skipped in short mode")
	}

	// random UUID
	id := "123e4567-e89b-12d3-a456-426614174000"
	parsed, err := uuid.ParseString(id)
	if err != nil {
		t.Fatalf("parse uuid failed: %v", err)
	}

	h := &Handler{
		clients: []*protocol.MemoryUser{{
			Email:   id,
			Account: &MemoryAccount{Id: id},
		}},
	}

	firstDiff := [16]byte(parsed)
	firstDiff[0] ^= 0xFF
	lastDiff := [16]byte(parsed)
	lastDiff[15] ^= 0xFF

	// limit to 1 CPU
	prev := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(prev)

	measure := func(uid [16]byte) float64 {
		// just high number of iterations
		loops := 1 << 10
		for {
			start := time.Now()
			for i := 0; i < loops; i++ {
				_, _ = h.authenticateUser(uid)
			}
			d := time.Since(start)
			// almost never reaches loops >= 1<< 24
			if d >= 50*time.Millisecond || loops >= 1<<24 {
				return float64(d.Nanoseconds()) / float64(loops)
			}
			loops *= 2
		}
	}
	// median to not count outliers and more reliable results
	// based on statistics, avg is too sensitive to outliers !!!
	median := func(in []float64) float64 {
		cp := append([]float64(nil), in...)
		sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
		return cp[len(cp)/2]
	}

	firstSamples := make([]float64, 0, 7)
	lastSamples := make([]float64, 0, 7)
	for i := 0; i < 7; i++ {
		// Alternate ordering to reduce bias
		if i%2 == 0 {
			firstSamples = append(firstSamples, measure(firstDiff))
			lastSamples = append(lastSamples, measure(lastDiff))
		} else {
			lastSamples = append(lastSamples, measure(lastDiff))
			firstSamples = append(firstSamples, measure(firstDiff))
		}
	}

	d1 := median(firstSamples)
	d2 := median(lastSamples)
	if d1 == 0 || d2 == 0 {
		t.Fatalf("invalid timing results (ns/op): first=%f last=%f", d1, d2)
	}
	if d1 > d2 {
		d1, d2 = d2, d1
	}

	// fail only on clear mismatch-position dependency.
	// not some number like 1.1 that is really close calls that could be just noise, but 1.8 is a clear sign of timing leak.
	// not 2 because it may be too loose and allow some actual dependency to pass
	if d2/d1 > 1.8 {
		t.Fatalf("timing differs by mismatch position (ns/op): first=%f last=%f", d1, d2)
	}
}
