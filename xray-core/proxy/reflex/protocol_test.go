package reflex

import (
	"encoding/binary"
	"testing"
)

func TestDetectProtocol(t *testing.T) {
	pd := NewProtocolDetector()

	// 1. Test Reflex Magic
	reflexData := make([]byte, 8)
	binary.BigEndian.PutUint32(reflexData, ReflexMagic)
	if pd.DetectProtocol(reflexData) != "reflex" {
		t.Error("failed to detect reflex protocol")
	}

	// 2. Test HTTP GET
	if pd.DetectProtocol([]byte("GET / index.html")) != "http" {
		t.Error("failed to detect http GET")
	}

	// 3. Test HTTP POST
	if pd.DetectProtocol([]byte("POST /api/v1")) != "http" {
		t.Error("failed to detect http POST")
	}

	// 4. Test TLS Handshake
	tlsData := []byte{0x16, 0x03, 0x01, 0x00, 0x4B}
	if pd.DetectProtocol(tlsData) != "tls" {
		t.Error("failed to detect tls handshake")
	}

	// 5. Test Unknown
	if pd.DetectProtocol([]byte{0x00, 0x01, 0x02, 0x03}) != "unknown" {
		t.Error("expected unknown for random bytes")
	}
}

func TestIsReflexHandshake(t *testing.T) {
	pd := NewProtocolDetector()

	// Valid handshake: Magic + Len(100)
	valid := make([]byte, 10)
	binary.BigEndian.PutUint32(valid[0:4], ReflexMagic)
	binary.BigEndian.PutUint16(valid[4:6], 100)

	if !pd.IsReflexHandshake(valid) {
		t.Error("expected true for valid reflex handshake")
	}

	// Invalid: Too short
	if pd.IsReflexHandshake(valid[:5]) {
		t.Error("expected false for short data")
	}

	// Invalid: Wrong Magic
	invalidMagic := make([]byte, 10)
	binary.BigEndian.PutUint32(invalidMagic[0:4], 0x12345678)
	if pd.IsReflexHandshake(invalidMagic) {
		t.Error("expected false for wrong magic")
	}

	// Invalid: Length too large (sanity check)
	largeLen := make([]byte, 10)
	binary.BigEndian.PutUint32(largeLen[0:4], ReflexMagic)
	binary.BigEndian.PutUint16(largeLen[4:6], 5000) // Default max is 4096
	if pd.IsReflexHandshake(largeLen) {
		t.Error("expected false for oversized length")
	}
}

func TestIsHTTPRequest(t *testing.T) {
	pd := NewProtocolDetector()

	validMethods := []string{"GET ", "POST", "PUT ", "CONNECT"}
	for _, m := range validMethods {
		if !pd.isHTTPRequest([]byte(m)) {
			t.Errorf("failed to recognize HTTP method: %s", m)
		}
	}

	if pd.isHTTPRequest([]byte("FAKE ")) {
		t.Error("expected false for non-HTTP method")
	}
}
