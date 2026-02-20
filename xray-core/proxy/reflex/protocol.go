package reflex

import (
	"encoding/binary"
	"strings"
)

// ProtocolDetector detects protocol type
type ProtocolDetector struct {
	minPeekSize int
}

// NewProtocolDetector creates detector
func NewProtocolDetector() *ProtocolDetector {
	return &ProtocolDetector{
		minPeekSize: 64,
	}
}

// DetectProtocol identifies protocol from peeked data
func (pd *ProtocolDetector) DetectProtocol(data []byte) string {
	if len(data) == 0 {
		return "unknown"
	}

	// Check magic number first (fastest)
	if pd.isReflexMagic(data) {
		return "reflex"
	}

	// Check HTTP-like
	if pd.isHTTPRequest(data) {
		return "http"
	}

	// Check TLS
	if pd.isTLS(data) {
		return "tls"
	}

	return "unknown"
}

// isReflexMagic checks for Reflex magic number
func (pd *ProtocolDetector) isReflexMagic(data []byte) bool {
	if len(data) < 4 {
		return false
	}

	magic := binary.BigEndian.Uint32(data[0:4])
	return magic == ReflexMagic
}

// isHTTPRequest checks for HTTP request
func (pd *ProtocolDetector) isHTTPRequest(data []byte) bool {
	if len(data) < 4 {
		return false
	}

	// Check common HTTP methods
	methods := []string{"GET ", "POST", "PUT ", "HEAD", "DELE", "PATC", "OPTI", "TRAC", "CONN"}

	dataStr := string(data[:4])
	for _, method := range methods {
		if strings.HasPrefix(dataStr, method[:4]) {
			return true
		}
	}

	return false
}

// isTLS checks for TLS handshake
func (pd *ProtocolDetector) isTLS(data []byte) bool {
	if len(data) < 3 {
		return false
	}

	// TLS record type: Handshake = 0x16
	// TLS version: TLS 1.0-1.3 = 0x0301-0x0303
	return data[0] == 0x16 && data[1] == 0x03
}

// IsReflexHandshake checks if this is a valid Reflex handshake
func (pd *ProtocolDetector) IsReflexHandshake(data []byte) bool {
	if len(data) < 6 {
		return false
	}

	// Check magic + length sanity
	if !pd.isReflexMagic(data) {
		return false
	}

	length := binary.BigEndian.Uint16(data[4:6])

	// Sanity check: length should be reasonable (< 4096)
	return length > 0 && length < 4096
}
