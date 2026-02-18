package inbound

import (
	"testing"
)

// Test Fallback Detection
// We want to ensure standard HTTP methods are NOT confused with Reflex Magic Bytes
func TestFallbackDetection(t *testing.T) {
	h := &Handler{}

	// List of common HTTP starts that should trigger Fallback
	httpProbes := map[string][]byte{
		"HTTP GET":  []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		"HTTP POST": []byte("POST /login HTTP/1.1\r\nContent-Length: 0\r\n\r\n"),
		"HTTP HEAD": []byte("HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		"HTTP PUT":  []byte("PUT /upload HTTP/1.1\r\n\r\n"),
		"TLS ClientHello": {
			0x16, 0x03, 0x01, 0x00, 0xa0, // Typical TLS handshake start
		},
	}

	for name, data := range httpProbes {
		t.Run(name, func(t *testing.T) {
			// 1. It must NOT be Reflex Magic
			if h.isReflexMagic(data) {
				t.Errorf("Error: %s was incorrectly identified as Reflex Protocol!", name)
			}

			// 2. It SHOULD be detected as a probe (if you have a helper for that)
			// Assuming you have logic like isHTTPPostLike or similar, strictly speaking
			// if it's NOT Reflex, it defaults to Fallback.
		})
	}
}

// Test Partial/Edge Case Magic
func TestPartialMagic(t *testing.T) {
	h := &Handler{}

	// Case: Sending only the first 2 bytes of the magic
	// The server should wait, not crash or accept it yet.
	// But since this function checks "is it magic?", it should return false for partial data.
	partial := []byte{0x52, 0x46} // "RF..."
	
	if h.isReflexMagic(partial) {
		t.Error("Error: Partial magic bytes incorrectly accepted as full valid magic.")
	}
}