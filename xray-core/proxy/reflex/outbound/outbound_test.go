package outbound

import (
	"context"
	"strings"
	"testing"

	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport"
)

func TestNewAndProcess(t *testing.T) {
	hAny, err := New(context.Background(), &reflex.OutboundConfig{
		Address: "127.0.0.1",
		Port:    443,
		Id:      "11111111-1111-1111-1111-111111111111",
	})
	if err != nil {
		t.Fatal(err)
	}
	h := hAny.(*Handler)
	if h.config == nil || h.config.Address != "127.0.0.1" {
		t.Fatal("expected outbound config")
	}

	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{}})
	err = h.Process(ctx, &transport.Link{}, nil)
	if err == nil || !strings.Contains(err.Error(), "dialer is nil") {
		t.Fatalf("unexpected process error: %v", err)
	}
}
