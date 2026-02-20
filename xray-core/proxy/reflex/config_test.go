package reflex

import (
	"testing"
)

// TestUserProtoGetters tests the generated protobuf getter methods for User
func TestUserProtoGetters(t *testing.T) {
	// Test with populated struct
	u := &User{Id: "test-uuid", Policy: "youtube"}
	if u.GetId() != "test-uuid" {
		t.Errorf("GetId() = %q, want %q", u.GetId(), "test-uuid")
	}
	if u.GetPolicy() != "youtube" {
		t.Errorf("GetPolicy() = %q, want %q", u.GetPolicy(), "youtube")
	}

	// Test with nil
	var nilUser *User
	if nilUser.GetId() != "" {
		t.Errorf("nil.GetId() should return empty string")
	}
	if nilUser.GetPolicy() != "" {
		t.Errorf("nil.GetPolicy() should return empty string")
	}
}

func TestUserProtoMethods(t *testing.T) {
	u := &User{Id: "test-id"}
	u.Reset()
	// After reset, fields should be zero
	if u.GetId() != "" {
		t.Errorf("after Reset, GetId() should be empty, got %q", u.GetId())
	}

	u.Id = "new-id"
	s := u.String()
	if s == "" {
		t.Error("String() should return non-empty")
	}

	u.ProtoMessage() // Should not panic

	r := u.ProtoReflect()
	if r == nil {
		t.Error("ProtoReflect() should not return nil")
	}

	_, indices := u.Descriptor()
	if indices == nil {
		t.Error("Descriptor() should return non-nil indices")
	}
}

// TestAccountProtoGetters tests the generated protobuf getter methods for Account
func TestAccountProtoGetters(t *testing.T) {
	a := &Account{Id: "acc-123"}
	if a.GetId() != "acc-123" {
		t.Errorf("GetId() = %q, want %q", a.GetId(), "acc-123")
	}

	var nilAccount *Account
	if nilAccount.GetId() != "" {
		t.Errorf("nil.GetId() should return empty string")
	}
}

func TestAccountProtoMethods(t *testing.T) {
	a := &Account{Id: "old-id"}
	a.Reset()
	if a.GetId() != "" {
		t.Errorf("after Reset, GetId() should be empty")
	}

	a.Id = "new-id"
	_ = a.String()
	a.ProtoMessage()
	r := a.ProtoReflect()
	if r == nil {
		t.Error("ProtoReflect() should not return nil")
	}
	_, indices := a.Descriptor()
	if len(indices) == 0 {
		t.Error("Descriptor() indices should be non-nil")
	}
}

// TestInboundConfigProtoGetters tests InboundConfig generated getters
func TestInboundConfigProtoGetters(t *testing.T) {
	clients := []*User{{Id: "u1"}, {Id: "u2"}}
	fallback := &Fallback{Dest: 8080}
	echBytes := []byte("ech-config-data")

	c := &InboundConfig{
		Clients:    clients,
		Fallback:   fallback,
		UseTls:     true,
		UseQuic:    false,
		ServerName: "example.com",
		EchConfig:  echBytes,
	}

	if len(c.GetClients()) != 2 {
		t.Errorf("GetClients() len = %d, want 2", len(c.GetClients()))
	}
	if c.GetFallback() != fallback {
		t.Error("GetFallback() mismatch")
	}
	if !c.GetUseTls() {
		t.Error("GetUseTls() should be true")
	}
	if c.GetUseQuic() {
		t.Error("GetUseQuic() should be false")
	}
	if c.GetServerName() != "example.com" {
		t.Errorf("GetServerName() = %q, want %q", c.GetServerName(), "example.com")
	}
	if string(c.GetEchConfig()) != string(echBytes) {
		t.Errorf("GetEchConfig() mismatch")
	}
}

func TestInboundConfigProtoGetters_Nil(t *testing.T) {
	var c *InboundConfig
	if c.GetClients() != nil {
		t.Error("nil.GetClients() should return nil")
	}
	if c.GetFallback() != nil {
		t.Error("nil.GetFallback() should return nil")
	}
	if c.GetUseTls() {
		t.Error("nil.GetUseTls() should return false")
	}
	if c.GetUseQuic() {
		t.Error("nil.GetUseQuic() should return false")
	}
	if c.GetServerName() != "" {
		t.Error("nil.GetServerName() should return empty")
	}
	if c.GetEchConfig() != nil {
		t.Error("nil.GetEchConfig() should return nil")
	}
}

func TestInboundConfigProtoMethods(t *testing.T) {
	c := &InboundConfig{UseTls: true, ServerName: "test.com"}
	c.Reset()
	if c.GetUseTls() {
		t.Error("after Reset, GetUseTls() should be false")
	}

	c.UseTls = true
	_ = c.String()
	c.ProtoMessage()
	r := c.ProtoReflect()
	if r == nil {
		t.Error("ProtoReflect() should not return nil")
	}
	_, indices := c.Descriptor()
	if len(indices) == 0 {
		t.Error("Descriptor() indices should be non-empty")
	}
}

// TestFallbackProtoGetters tests Fallback generated getters
func TestFallbackProtoGetters(t *testing.T) {
	f := &Fallback{Dest: 9090}
	if f.GetDest() != 9090 {
		t.Errorf("GetDest() = %d, want 9090", f.GetDest())
	}

	var nilFallback *Fallback
	if nilFallback.GetDest() != 0 {
		t.Errorf("nil.GetDest() should return 0")
	}
}

func TestFallbackProtoMethods(t *testing.T) {
	f := &Fallback{Dest: 443}
	f.Reset()
	if f.GetDest() != 0 {
		t.Errorf("after Reset, GetDest() should be 0")
	}

	f.Dest = 443
	_ = f.String()
	f.ProtoMessage()
	r := f.ProtoReflect()
	if r == nil {
		t.Error("ProtoReflect() should not return nil")
	}
	_, indices := f.Descriptor()
	if len(indices) == 0 {
		t.Error("Descriptor() indices should be non-empty")
	}
}

// TestOutboundConfigProtoGetters tests OutboundConfig generated getters
func TestOutboundConfigProtoGetters(t *testing.T) {
	c := &OutboundConfig{
		Address: "192.168.1.1",
		Port:    1443,
		Id:      "client-uuid",
	}
	if c.GetAddress() != "192.168.1.1" {
		t.Errorf("GetAddress() = %q, want %q", c.GetAddress(), "192.168.1.1")
	}
	if c.GetPort() != 1443 {
		t.Errorf("GetPort() = %d, want 1443", c.GetPort())
	}
	if c.GetId() != "client-uuid" {
		t.Errorf("GetId() = %q, want %q", c.GetId(), "client-uuid")
	}
}

func TestOutboundConfigProtoGetters_Nil(t *testing.T) {
	var c *OutboundConfig
	if c.GetAddress() != "" {
		t.Error("nil.GetAddress() should return empty string")
	}
	if c.GetPort() != 0 {
		t.Error("nil.GetPort() should return 0")
	}
	if c.GetId() != "" {
		t.Error("nil.GetId() should return empty string")
	}
}

func TestOutboundConfigProtoMethods(t *testing.T) {
	c := &OutboundConfig{Address: "localhost", Port: 8080, Id: "abc"}
	c.Reset()
	if c.GetAddress() != "" {
		t.Errorf("after Reset, GetAddress() should be empty")
	}

	c.Address = "localhost"
	c.Port = 8080
	c.Id = "abc"
	_ = c.String()
	c.ProtoMessage()
	r := c.ProtoReflect()
	if r == nil {
		t.Error("ProtoReflect() should not return nil")
	}
	_, indices := c.Descriptor()
	if len(indices) == 0 {
		t.Error("Descriptor() indices should be non-empty")
	}
}
