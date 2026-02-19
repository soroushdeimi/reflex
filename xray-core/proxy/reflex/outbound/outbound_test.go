package outbound

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/proxy/reflex"
)

func TestHelperFunctions(t *testing.T) {
	// 1. Test Key Generation
	priv, pub, err := generateKeyPair()
	if err != nil {
		t.Fatalf("generateKeyPair failed: %v", err)
	}
	if len(priv) != 32 || len(pub) != 32 {
		t.Error("Invalid key sizes")
	}

	// 2. Test Shared Key Derivation
	shared, err := deriveSharedKey(priv, pub)
	if err != nil {
		t.Fatalf("deriveSharedKey failed: %v", err)
	}
	if len(shared) != 32 {
		t.Error("Invalid shared key size")
	}

	// 3. Test Session Key Derivation (HKDF)
	nonce := make([]byte, 16)
	sessKey, err := deriveSessionKey(shared, nonce, []byte("test"))
	if err != nil {
		t.Fatalf("deriveSessionKey failed: %v", err)
	}
	if len(sessKey) != 32 {
		t.Error("Invalid session key size")
	}
}

func TestEncodeDest(t *testing.T) {
	tests := []struct {
		name string
		dest net.Destination
	}{
		{"IPv4", net.TCPDestination(net.ParseAddress("1.2.3.4"), 80)},
		{"IPv6", net.TCPDestination(net.ParseAddress("::1"), 443)},
		{"Domain", net.TCPDestination(net.DomainAddress("example.com"), 8080)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := encodeDest(tt.dest)
			if len(b) == 0 {
				t.Error("Encoded bytes should not be empty")
			}
		})
	}
}

func TestNewHandler(t *testing.T) {
	ctx := context.Background()

	// Test valid config
	config := &reflex.OutboundConfig{
		Address: "127.0.0.1",
		Port:    10080,
	}
	h, err := New(ctx, config)
	if err != nil || h == nil {
		t.Fatal("Failed to create handler with valid config")
	}

	// Test nil config
	_, err = New(ctx, nil)
	if err == nil {
		t.Error("Expected error for nil config")
	}
}
