package tests

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/proxy/reflex/outbound"
)

func TestNewAndProcess(t *testing.T) {
	cfg := &reflex.OutboundConfig{
		Address: "127.0.0.1",
		Port:    443,
		Id:      "test-user",
	}

	out, err := outbound.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	if out == nil {
		t.Fatal("expected non-nil outbound handler")
	}

	// Test basic handler creation - Process is tested in integration tests
}
