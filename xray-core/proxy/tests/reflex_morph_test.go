package tests

import (
	"testing"
	"time"

	"github.com/xtls/xray-core/proxy/reflex"
)

func TestReflexTrafficProfileOverrides(t *testing.T) {
	profile, ok := reflex.Profiles["http2-api"]
	if !ok {
		t.Fatal("expected http2-api profile to exist")
	}

	// Override size and delay once.
	profile.SetNextPacketSize(1234)
	if got := profile.GetPacketSize(); got != 1234 {
		t.Fatalf("expected override packet size 1234, got %d", got)
	}

	// Next call should use distribution, not override; just ensure positive.
	if got := profile.GetPacketSize(); got <= 0 {
		t.Fatalf("expected positive packet size from distribution, got %d", got)
	}

	profile.SetNextDelay(42 * time.Millisecond)
	if got := profile.GetDelay(); got != 42*time.Millisecond {
		t.Fatalf("expected override delay 42ms, got %v", got)
	}
	if got := profile.GetDelay(); got < 0 {
		t.Fatalf("expected non-negative delay from distribution, got %v", got)
	}
}

func TestReflexAddPadding(t *testing.T) {
	data := []byte("abc")

	// No-op when target <= len(data).
	if got := reflex.AddPadding(data, len(data)); len(got) != len(data) {
		t.Fatalf("expected unchanged size when target == len, got %d", len(got))
	}

	// Padding to larger size.
	target := 10
	padded := reflex.AddPadding(data, target)
	if len(padded) != target {
		t.Fatalf("expected length %d after padding, got %d", target, len(padded))
	}
	if string(padded[:len(data)]) != string(data) {
		t.Fatalf("expected original prefix %q, got %q", string(data), string(padded[:len(data)]))
	}
}
