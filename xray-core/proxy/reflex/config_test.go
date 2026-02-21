package reflex

import (
	"testing"

	"google.golang.org/protobuf/proto"
)

func TestConfigProtoGeneratedMethods(t *testing.T) {
	u := &User{Id: "u1", Policy: "http2-api"}
	if u.GetId() != "u1" || u.GetPolicy() != "http2-api" {
		t.Fatal("user getters returned unexpected values")
	}
	if s := u.String(); s == "" {
		t.Fatal("user string should not be empty")
	}
	_ = u.ProtoReflect()
	_, _ = u.Descriptor()
	u.Reset()
	if u.GetId() != "" || u.GetPolicy() != "" {
		t.Fatal("user reset failed")
	}

	a := &Account{Id: "acc1"}
	if a.GetId() != "acc1" {
		t.Fatal("account getter returned unexpected value")
	}
	_ = a.String()
	_ = a.ProtoReflect()
	_, _ = a.Descriptor()
	a.Reset()
	if a.GetId() != "" {
		t.Fatal("account reset failed")
	}

	in := &InboundConfig{
		Clients:  []*User{{Id: "u2", Policy: "normal"}},
		Fallback: &Fallback{Dest: 443},
	}
	if len(in.GetClients()) != 1 || in.GetFallback() == nil || in.GetFallback().GetDest() != 443 {
		t.Fatal("inbound getters returned unexpected values")
	}
	_ = in.String()
	_ = in.ProtoReflect()
	_, _ = in.Descriptor()
	in.Reset()
	if in.GetClients() != nil || in.GetFallback() != nil {
		t.Fatal("inbound reset failed")
	}

	fb := &Fallback{Dest: 8443}
	if fb.GetDest() != 8443 {
		t.Fatal("fallback getter returned unexpected value")
	}
	_ = fb.String()
	_ = fb.ProtoReflect()
	_, _ = fb.Descriptor()
	fb.Reset()
	if fb.GetDest() != 0 {
		t.Fatal("fallback reset failed")
	}

	out := &OutboundConfig{Address: "127.0.0.1", Port: 8080, Id: "out1"}
	if out.GetAddress() != "127.0.0.1" || out.GetPort() != 8080 || out.GetId() != "out1" {
		t.Fatal("outbound getters returned unexpected values")
	}
	_ = out.String()
	_ = out.ProtoReflect()
	_, _ = out.Descriptor()
	out.Reset()
	if out.GetAddress() != "" || out.GetPort() != 0 || out.GetId() != "" {
		t.Fatal("outbound reset failed")
	}
}

func TestConfigProtoNilReceiversAndDescriptor(t *testing.T) {
	var u *User
	if u.GetId() != "" || u.GetPolicy() != "" {
		t.Fatal("nil user getters should return zero values")
	}
	_ = u.ProtoReflect()

	var a *Account
	if a.GetId() != "" {
		t.Fatal("nil account getter should return zero value")
	}
	_ = a.ProtoReflect()

	var in *InboundConfig
	if in.GetClients() != nil || in.GetFallback() != nil {
		t.Fatal("nil inbound getters should return zero values")
	}
	_ = in.ProtoReflect()

	var fb *Fallback
	if fb.GetDest() != 0 {
		t.Fatal("nil fallback getter should return zero value")
	}
	_ = fb.ProtoReflect()

	var out *OutboundConfig
	if out.GetAddress() != "" || out.GetPort() != 0 || out.GetId() != "" {
		t.Fatal("nil outbound getters should return zero values")
	}
	_ = out.ProtoReflect()

	if len(file_proxy_reflex_config_proto_rawDescGZIP()) == 0 {
		t.Fatal("raw descriptor gzip should not be empty")
	}
	if File_proxy_reflex_config_proto == nil {
		t.Fatal("file descriptor should be initialized")
	}
}

func TestConfigProtoMarshalUnmarshal(t *testing.T) {
	src := &InboundConfig{
		Clients: []*User{
			{Id: "10000001", Policy: "normal"},
			{Id: "10000002", Policy: "http2-api"},
		},
		Fallback: &Fallback{Dest: 9443},
	}

	b, err := proto.Marshal(src)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	var dst InboundConfig
	if err := proto.Unmarshal(b, &dst); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if len(dst.Clients) != 2 || dst.Fallback == nil || dst.Fallback.Dest != 9443 {
		t.Fatal("decoded inbound config mismatch")
	}
}
