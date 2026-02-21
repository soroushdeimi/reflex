package reflex

import (
	"crypto/tls"
	"testing"
)

func TestGenerateECHKeySet(t *testing.T) {
	ks, err := GenerateECHKeySet(1, "example.com")
	if err != nil {
		t.Fatalf("GenerateECHKeySet failed: %v", err)
	}
	if ks == nil {
		t.Fatal("key set is nil")
	}
	if ks.ConfigID != 1 {
		t.Fatalf("expected ConfigID 1, got %d", ks.ConfigID)
	}
	if ks.PublicName != "example.com" {
		t.Fatalf("expected public name 'example.com', got %s", ks.PublicName)
	}
	if len(ks.PrivateKey) == 0 {
		t.Fatal("private key is empty")
	}
	if len(ks.Config) == 0 {
		t.Fatal("config is empty")
	}
}

func TestGenerateECHKeySetUniqueness(t *testing.T) {
	ks1, _ := GenerateECHKeySet(1, "example.com")
	ks2, _ := GenerateECHKeySet(1, "example.com")

	if string(ks1.PrivateKey) == string(ks2.PrivateKey) {
		t.Fatal("two key sets should have different private keys")
	}
}

func TestMarshalECHConfigList(t *testing.T) {
	ks, _ := GenerateECHKeySet(1, "example.com")

	configList, err := MarshalECHConfigList(ks.Config)
	if err != nil {
		t.Fatalf("MarshalECHConfigList failed: %v", err)
	}
	if len(configList) == 0 {
		t.Fatal("config list is empty")
	}
	if len(configList) <= len(ks.Config) {
		t.Fatal("config list should be longer than single config (includes length prefix)")
	}
}

func TestMarshalECHConfigListMultiple(t *testing.T) {
	ks1, _ := GenerateECHKeySet(1, "example.com")
	ks2, _ := GenerateECHKeySet(2, "cdn.example.com")

	configList, err := MarshalECHConfigList(ks1.Config, ks2.Config)
	if err != nil {
		t.Fatalf("MarshalECHConfigList with multiple configs failed: %v", err)
	}
	if len(configList) == 0 {
		t.Fatal("config list is empty")
	}
}

func TestApplyECHServer(t *testing.T) {
	ks, _ := GenerateECHKeySet(1, "example.com")

	tlsConfig := &tls.Config{}
	err := ApplyECHServer(tlsConfig, ks)
	if err != nil {
		t.Fatalf("ApplyECHServer failed: %v", err)
	}

	if len(tlsConfig.EncryptedClientHelloKeys) != 1 {
		t.Fatalf("expected 1 ECH key, got %d", len(tlsConfig.EncryptedClientHelloKeys))
	}
	if tlsConfig.MinVersion != tls.VersionTLS13 {
		t.Fatal("expected TLS 1.3 minimum version")
	}
}

func TestApplyECHServerEmpty(t *testing.T) {
	tlsConfig := &tls.Config{}
	err := ApplyECHServer(tlsConfig)
	if err != nil {
		t.Fatal("ApplyECHServer with no keys should not error")
	}
	if len(tlsConfig.EncryptedClientHelloKeys) != 0 {
		t.Fatal("should have no ECH keys")
	}
}

func TestApplyECHClient(t *testing.T) {
	ks, _ := GenerateECHKeySet(1, "example.com")
	configList, _ := MarshalECHConfigList(ks.Config)

	tlsConfig := &tls.Config{}
	ApplyECHClient(tlsConfig, configList)

	if len(tlsConfig.EncryptedClientHelloConfigList) == 0 {
		t.Fatal("expected non-empty ECH config list")
	}
	if tlsConfig.MinVersion != tls.VersionTLS13 {
		t.Fatal("expected TLS 1.3 minimum version")
	}
}

func TestNewServerECHConfig(t *testing.T) {
	cfg, err := NewServerECHConfig("cdn.example.com", 42)
	if err != nil {
		t.Fatalf("NewServerECHConfig failed: %v", err)
	}
	if !cfg.Enabled {
		t.Fatal("config should be enabled")
	}
	if cfg.PublicName != "cdn.example.com" {
		t.Fatalf("expected public name 'cdn.example.com', got %s", cfg.PublicName)
	}
	if cfg.ConfigID != 42 {
		t.Fatalf("expected config ID 42, got %d", cfg.ConfigID)
	}
	if cfg.KeySet == nil {
		t.Fatal("key set is nil")
	}
	if len(cfg.ConfigList) == 0 {
		t.Fatal("config list is empty")
	}
}

func TestECHServerClientRoundTrip(t *testing.T) {
	serverCfg, err := NewServerECHConfig("example.com", 1)
	if err != nil {
		t.Fatal(err)
	}

	// Server-side TLS config
	serverTLS := &tls.Config{}
	if err := ApplyECHServer(serverTLS, serverCfg.KeySet); err != nil {
		t.Fatal(err)
	}

	// Client-side TLS config using the config list from the server
	clientTLS := &tls.Config{}
	ApplyECHClient(clientTLS, serverCfg.ConfigList)

	// Verify both sides are configured
	if len(serverTLS.EncryptedClientHelloKeys) == 0 {
		t.Fatal("server should have ECH keys")
	}
	if len(clientTLS.EncryptedClientHelloConfigList) == 0 {
		t.Fatal("client should have ECH config list")
	}
}
