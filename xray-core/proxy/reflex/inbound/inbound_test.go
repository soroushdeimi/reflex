package inbound

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/proxy/reflex"
)

func TestMemoryAccountAndNewHandler(t *testing.T) {
	cfg := &reflex.InboundConfig{
		Clients: []*reflex.User{
			{Id: "11111111-1111-1111-1111-111111111111", Policy: "strict"},
		},
		Fallback: &reflex.Fallback{Dest: 8080},
	}
	in, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	h := in.(*Handler)
	if len(h.clients) != 1 {
		t.Fatalf("unexpected clients len: %d", len(h.clients))
	}
	if h.fallback == nil || h.fallback.Dest != 8080 {
		t.Fatal("fallback config not applied")
	}

	acc1 := &MemoryAccount{ID: "a"}
	acc2 := &MemoryAccount{ID: "a"}
	if !acc1.Equals(acc2) {
		t.Fatal("equal accounts should match")
	}
	if acc1.ToProto() == nil {
		t.Fatal("account proto should not be nil")
	}
}

func TestNetwork(t *testing.T) {
	h := &Handler{}
	nw := h.Network()
	if len(nw) != 1 || nw[0] != net.Network_TCP {
		t.Fatalf("unexpected network list: %#v", nw)
	}
}
