package tests

import (
	"testing"

	"github.com/xtls/xray-core/proxy/reflex"
)

func TestConfigMessagesGettersAndReset(t *testing.T) {
	u := &reflex.User{Id: "u1", Policy: "youtube"}
	if u.GetId() != "u1" || u.GetPolicy() != "youtube" {
		t.Fatal("user getters returned unexpected values")
	}
	_ = u.String()
	_ = u.ProtoReflect()
	_, _ = u.Descriptor()
	u.Reset()
	if u.GetId() != "" || u.GetPolicy() != "" {
		t.Fatal("user reset did not clear fields")
	}

	a := &reflex.Account{Id: "acc1"}
	if a.GetId() != "acc1" {
		t.Fatal("account getter returned unexpected value")
	}
	_ = a.String()
	_ = a.ProtoReflect()
	_, _ = a.Descriptor()
	a.Reset()
	if a.GetId() != "" {
		t.Fatal("account reset did not clear fields")
	}

	fb := &reflex.Fallback{Dest: 443}
	if fb.GetDest() != 443 {
		t.Fatal("fallback getter returned unexpected value")
	}
	_ = fb.String()
	_ = fb.ProtoReflect()
	_, _ = fb.Descriptor()
	fb.Reset()
	if fb.GetDest() != 0 {
		t.Fatal("fallback reset did not clear fields")
	}

	in := &reflex.InboundConfig{Clients: []*reflex.User{{Id: "u2"}}, Fallback: &reflex.Fallback{Dest: 80}}
	if len(in.GetClients()) != 1 || in.GetFallback() == nil {
		t.Fatal("inbound getters returned unexpected values")
	}
	_ = in.String()
	_ = in.ProtoReflect()
	_, _ = in.Descriptor()
	in.Reset()
	if in.GetClients() != nil || in.GetFallback() != nil {
		t.Fatal("inbound reset did not clear fields")
	}

	out := &reflex.OutboundConfig{Address: "example.com", Port: 6969, Id: "u3"}
	if out.GetAddress() != "example.com" || out.GetPort() != 6969 || out.GetId() != "u3" {
		t.Fatal("outbound getters returned unexpected values")
	}
	_ = out.String()
	_ = out.ProtoReflect()
	_, _ = out.Descriptor()
	out.Reset()
	if out.GetAddress() != "" || out.GetPort() != 0 || out.GetId() != "" {
		t.Fatal("outbound reset did not clear fields")
	}
}

func TestConfigNilGettersAndDescriptorInit(t *testing.T) {
	var u *reflex.User
	var a *reflex.Account
	var fb *reflex.Fallback
	var in *reflex.InboundConfig
	var out *reflex.OutboundConfig

	if u.GetId() != "" || u.GetPolicy() != "" {
		t.Fatal("nil user getters should return zero values")
	}
	if a.GetId() != "" {
		t.Fatal("nil account getter should return zero value")
	}
	if fb.GetDest() != 0 {
		t.Fatal("nil fallback getter should return zero value")
	}
	if in.GetClients() != nil || in.GetFallback() != nil {
		t.Fatal("nil inbound getters should return zero values")
	}
	if out.GetAddress() != "" || out.GetPort() != 0 || out.GetId() != "" {
		t.Fatal("nil outbound getters should return zero values")
	}
}
