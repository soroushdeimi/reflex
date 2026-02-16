package outbound

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/proxy/reflex"
)

func TestNewAndProcess(t *testing.T) {
	cfg := &reflex.OutboundConfig{
		Address: "127.0.0.1",
		Port:    443,
		Id:      "test-user",
	}

	out, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	h, ok := out.(*Handler)
	if !ok {
		t.Fatalf("unexpected outbound type: %T", out)
	}
	if h.config != cfg {
		t.Fatal("handler did not keep config pointer")
	}

	if err := h.Process(context.Background(), nil, nil); err != nil {
		t.Fatalf("Process returned error: %v", err)
	}
}
