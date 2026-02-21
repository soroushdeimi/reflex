package reflex_test

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/proxy/reflex/outbound"
)

func TestNewOutbound(t *testing.T) {
	ctx := context.Background()
	config := &reflex.OutboundConfig{
		Address: "127.0.0.1",
		Port:    443,
		Id:      "test-id",
	}

	h, err := outbound.New(ctx, config)
	if err != nil {
		t.Fatalf("New outbound failed: %v", err)
	}

	if h == nil {
		t.Error("outbound handler is nil")
	}
}

func TestReflexOutboundConfigBuild(t *testing.T) {
	config := &reflex.OutboundConfig{
		Address: "1.2.3.4",
		Port:    443,
		Id:      "test",
	}
	if config.Address != "1.2.3.4" || config.Port != 443 || config.Id != "test" {
		t.Error("proto config mismatch")
	}
}
