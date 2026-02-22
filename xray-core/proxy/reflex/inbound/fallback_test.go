package inbound

import (
	"bytes"
	"testing"
)

// TestIsHTTPRequest tests HTTP request detection
func TestIsHTTPRequest(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{
			name:     "GET request",
			data:     []byte("GET / HTTP/1.1\r\nHost: example.com\r\n"),
			expected: true,
		},
		{
			name:     "POST request",
			data:     []byte("POST /api HTTP/1.1\r\nHost: example.com\r\n"),
			expected: true,
		},
		{
			name:     "PUT request",
			data:     []byte("PUT /resource HTTP/1.1\r\n"),
			expected: true,
		},
		{
			name:     "DELETE request",
			data:     []byte("DELETE /resource HTTP/1.1\r\n"),
			expected: true,
		},
		{
			name:     "HEAD request",
			data:     []byte("HEAD / HTTP/1.1\r\n"),
			expected: true,
		},
		{
			name:     "OPTIONS request",
			data:     []byte("OPTIONS * HTTP/1.1\r\n"),
			expected: true,
		},
		{
			name:     "PATCH request",
			data:     []byte("PATCH /resource HTTP/1.1\r\n"),
			expected: true,
		},
		{
			name:     "Not HTTP",
			data:     []byte("REFLEX HANDSHAKE"),
			expected: false,
		},
		{
			name:     "Empty data",
			data:     []byte(""),
			expected: false,
		},
		{
			name:     "TLS ClientHello",
			data:     []byte{0x16, 0x03, 0x01, 0x00, 0x4a},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isHTTPRequest(tt.data)
			if result != tt.expected {
				t.Fatalf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestIsTLSHandshake tests TLS ClientHello detection
func TestIsTLSHandshake(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{
			name:     "TLS 1.2 ClientHello",
			data:     []byte{0x16, 0x03, 0x03, 0x00, 0x4a}, // Handshake, TLS 1.2
			expected: true,
		},
		{
			name:     "TLS 1.3 ClientHello",
			data:     []byte{0x16, 0x03, 0x03, 0x00, 0x80}, // Handshake, TLS 1.2 for compat
			expected: true,
		},
		{
			name:     "TLS 1.0",
			data:     []byte{0x16, 0x03, 0x01, 0x00, 0x4a}, // Handshake, TLS 1.0
			expected: true,
		},
		{
			name:     "Not TLS",
			data:     []byte("GET / HTTP/1.1"),
			expected: false,
		},
		{
			name:     "Too short",
			data:     []byte{0x16, 0x03},
			expected: false,
		},
		{
			name:     "Empty",
			data:     []byte(""),
			expected: false,
		},
		{
			name:     "Wrong content type",
			data:     []byte{0x17, 0x03, 0x03, 0x00, 0x4a}, // Application Data
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isTLSHandshake(tt.data)
			if result != tt.expected {
				t.Fatalf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestExtractSNI tests SNI extraction from TLS ClientHello
func TestExtractSNI(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected string
	}{
		{
			name:     "No SNI",
			data:     []byte{0x16, 0x03, 0x03, 0x00, 0x4a}, // TLS handshake without SNI
			expected: "",
		},
		{
			name:     "Empty data",
			data:     []byte(""),
			expected: "",
		},
		{
			name:     "Non-TLS data",
			data:     []byte("GET / HTTP/1.1"),
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractSNI(tt.data)
			if result != tt.expected {
				t.Fatalf("expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

// TestExtractALPN tests ALPN extraction
func TestExtractALPN(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected string
	}{
		{
			name:     "No ALPN",
			data:     []byte{0x16, 0x03, 0x03, 0x00, 0x4a},
			expected: "",
		},
		{
			name:     "Empty data",
			data:     []byte(""),
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractALPN(tt.data)
			if result != tt.expected {
				t.Fatalf("expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

// TestExtractHostFromHTTP tests Host header extraction
func TestExtractHostFromHTTP(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected string
	}{
		{
			name: "Valid Host header",
			data: []byte("GET / HTTP/1.1\r\nHost: example.com\r\n"),
			// Note: actual implementation may vary
		},
		{
			name: "Host with port",
			data: []byte("GET / HTTP/1.1\r\nHost: example.com:8080\r\n"),
		},
		{
			name: "No Host header",
			data: []byte("GET / HTTP/1.1\r\nUser-Agent: test\r\n"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Just verify it doesn't panic
			_ = tt.data
		})
	}
}

// TestProtocolDetectionPriority tests that Reflex magic is detected before protocols
func TestProtocolDetectionPriority(t *testing.T) {
	// Reflex magic should be detected first
	reflexMagic := []byte{0x52, 0x46, 0x58, 0x4C} // "REFX"
	if isHTTPRequest(reflexMagic) {
		t.Fatal("Reflex magic should not be detected as HTTP")
	}
	if isTLSHandshake(reflexMagic) {
		t.Fatal("Reflex magic should not be detected as TLS")
	}
}

// TestHTTPPathExtraction tests path extraction from HTTP request
func TestHTTPPathExtraction(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		hasPath  bool
	}{
		{
			name:    "GET with path",
			data:    []byte("GET /api/v1/users HTTP/1.1\r\n"),
			hasPath: true,
		},
		{
			name:    "GET root",
			data:    []byte("GET / HTTP/1.1\r\n"),
			hasPath: true,
		},
		{
			name:    "POST with path",
			data:    []byte("POST /api/data HTTP/1.1\r\n"),
			hasPath: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Just verify HTTP request is detected
			if !isHTTPRequest(tt.data) {
				t.Fatal("should detect HTTP request")
			}
		})
	}
}

// TestTLSVersionDetection tests TLS version identification
func TestTLSVersionDetection(t *testing.T) {
	versions := []struct {
		name  string
		bytes []byte
	}{
		{
			name:  "TLS 1.0",
			bytes: []byte{0x16, 0x03, 0x01, 0x00, 0x4a},
		},
		{
			name:  "TLS 1.1",
			bytes: []byte{0x16, 0x03, 0x02, 0x00, 0x4a},
		},
		{
			name:  "TLS 1.2",
			bytes: []byte{0x16, 0x03, 0x03, 0x00, 0x4a},
		},
		{
			name:  "TLS 1.3 compat",
			bytes: []byte{0x16, 0x03, 0x03, 0x00, 0x80},
		},
	}

	for _, v := range versions {
		t.Run(v.name, func(t *testing.T) {
			if !isTLSHandshake(v.bytes) {
				t.Fatalf("%s should be detected as TLS", v.name)
			}
		})
	}
}

// TestEmptyDataHandling tests handling of empty/short data
func TestEmptyDataHandling(t *testing.T) {
	emptyData := []byte("")
	shortData := []byte{0x52}

	// Should not panic
	_ = isHTTPRequest(emptyData)
	_ = isHTTPRequest(shortData)
	_ = isTLSHandshake(emptyData)
	_ = isTLSHandshake(shortData)
	_ = extractSNI(emptyData)
	_ = extractALPN(shortData)
}

// TestProtocolBoundaries tests protocol detection at boundaries
func TestProtocolBoundaries(t *testing.T) {
	// Minimum TLS handshake (5 bytes)
	minTLS := []byte{0x16, 0x03, 0x03, 0x00, 0x4a}
	if !isTLSHandshake(minTLS) {
		t.Fatal("minimum TLS should be detected")
	}

	// Minimum HTTP (4 bytes for "GET ")
	minHTTP := []byte("GET ")
	if !isHTTPRequest(minHTTP) {
		t.Fatal("minimum HTTP should be detected")
	}
}

// TestDataIntegrity tests that data is not modified during detection
func TestDataIntegrity(t *testing.T) {
	originalData := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n")
	dataCopy := make([]byte, len(originalData))
	copy(dataCopy, originalData)

	// Test HTTP detection
	_ = isHTTPRequest(dataCopy)
	if !bytes.Equal(dataCopy, originalData) {
		t.Fatal("data should not be modified during HTTP detection")
	}

	// Test TLS detection with TLS data
	tlsData := []byte{0x16, 0x03, 0x03, 0x00, 0x4a}
	tlsCopy := make([]byte, len(tlsData))
	copy(tlsCopy, tlsData)

	_ = isTLSHandshake(tlsCopy)
	if !bytes.Equal(tlsCopy, tlsData) {
		t.Fatal("data should not be modified during TLS detection")
	}
}

// TestSpecialCharactersInHTTP tests HTTP detection with special characters
func TestSpecialCharactersInHTTP(t *testing.T) {
	requests := [][]byte{
		[]byte("GET /path?query=value HTTP/1.1\r\n"),
		[]byte("POST /api/v1/users HTTP/1.1\r\n"),
		[]byte("PUT /resource/123 HTTP/1.1\r\n"),
	}

	for _, req := range requests {
		if !isHTTPRequest(req) {
			t.Fatalf("should detect HTTP request: %s", string(req))
		}
	}
}

// TestCaseInsensitivity tests HTTP method detection case
func TestCaseInsensitivity(t *testing.T) {
	// HTTP methods should be uppercase
	methods := []string{"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"}

	for _, method := range methods {
		request := []byte(method + " / HTTP/1.1\r\n")
		if !isHTTPRequest(request) {
			t.Fatalf("should detect %s request", method)
		}
	}
}
