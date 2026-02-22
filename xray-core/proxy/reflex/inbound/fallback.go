package inbound

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// isHTTPRequest checks if the data looks like an HTTP request
func isHTTPRequest(data []byte) bool {
	if len(data) < 4 {
		return false
	}

	// Check for HTTP methods
	methods := []string{"GET ", "POST", "PUT ", "HEAD", "DELE", "OPTI", "PATC", "TRAC", "CONN"}
	for _, method := range methods {
		if bytes.HasPrefix(data, []byte(method)) {
			return true
		}
	}

	return false
}

// isTLSHandshake checks if the data looks like a TLS ClientHello
func isTLSHandshake(data []byte) bool {
	if len(data) < 5 {
		return false
	}

	// TLS record: [ContentType(1)] [Version(2)] [Length(2)] [Handshake]
	// ContentType: 0x16 (Handshake)
	// Version: 0x0301 (TLS 1.0), 0x0302 (TLS 1.1), 0x0303 (TLS 1.2), 0x0304 (TLS 1.3)

	if data[0] != 0x16 {
		return false
	}

	// Check TLS version (must be >= 0x03 for TLS 1.0 or later)
	if data[1] < 0x03 {
		return false
	}
	if data[2] < 0x00 {
		return false
	}

	return true
}

// extractSNI extracts the SNI (Server Name Indication) from TLS ClientHello
func extractSNI(data []byte) string {
	if len(data) < 43 {
		return ""
	}

	// Skip to extensions (complex parsing, simplified here)
	// TLS record header (5 bytes) + Handshake header (4 bytes) + ClientHello fixed part
	pos := 43

	// Skip session ID
	if pos >= len(data) {
		return ""
	}
	sessionIDLen := int(data[pos])
	pos += 1 + sessionIDLen

	// Skip cipher suites
	if pos+2 > len(data) {
		return ""
	}
	cipherSuitesLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2 + cipherSuitesLen

	// Skip compression methods
	if pos+1 > len(data) {
		return ""
	}
	compressionMethodsLen := int(data[pos])
	pos += 1 + compressionMethodsLen

	// Extensions
	if pos+2 > len(data) {
		return ""
	}
	extensionsLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2

	// Parse extensions
	endPos := pos + extensionsLen
	for pos+4 <= endPos && pos+4 <= len(data) {
		extType := int(data[pos])<<8 | int(data[pos+1])
		extLen := int(data[pos+2])<<8 | int(data[pos+3])
		pos += 4

		if extType == 0 { // SNI extension
			if pos+extLen > len(data) {
				return ""
			}
			// SNI list length (2 bytes)
			if pos+2 > len(data) {
				return ""
			}
			pos += 2

			// SNI type (1 byte, 0x00 for hostname)
			if pos >= len(data) || data[pos] != 0x00 {
				return ""
			}
			pos++

			// SNI length (2 bytes)
			if pos+2 > len(data) {
				return ""
			}
			sniLen := int(data[pos])<<8 | int(data[pos+1])
			pos += 2

			// SNI hostname
			if pos+sniLen > len(data) {
				return ""
			}
			return string(data[pos : pos+sniLen])
		}

		pos += extLen
	}

	return ""
}

// extractALPN extracts the ALPN (Application-Layer Protocol Negotiation) from TLS ClientHello
func extractALPN(data []byte) string {
	// Similar to extractSNI but looking for ALPN extension (type 16)
	// Simplified implementation - returns empty string for now
	// Full implementation would parse TLS extensions looking for ALPN
	return ""
}

// extractHTTPHost extracts the Host header from HTTP request
func extractHTTPHost(data []byte) string {
	lines := bytes.Split(data, []byte("\r\n"))
	for _, line := range lines {
		if bytes.HasPrefix(bytes.ToLower(line), []byte("host:")) {
			host := string(bytes.TrimSpace(line[5:]))
			return host
		}
	}
	return ""
}

// extractHTTPPath extracts the path from HTTP request line
func extractHTTPPath(data []byte) string {
	// Parse "METHOD /path HTTP/1.1"
	parts := bytes.SplitN(data, []byte(" "), 3)
	if len(parts) >= 2 {
		return string(parts[1])
	}
	return "/"
}

// findFallback finds the appropriate fallback configuration
func (h *Handler) findFallback(name, alpn, path string) *Fallback {
	if h.fallbacks == nil {
		return nil
	}

	// Try exact match first
	if apfb, ok := h.fallbacks[name]; ok {
		if pfb, ok := apfb[alpn]; ok {
			if fb, ok := pfb[path]; ok {
				return fb
			}
			// Try default path
			if fb, ok := pfb[""]; ok {
				return fb
			}
		}
		// Try default alpn
		if pfb, ok := apfb[""]; ok {
			if fb, ok := pfb[path]; ok {
				return fb
			}
			if fb, ok := pfb[""]; ok {
				return fb
			}
		}
	}

	// Try default name
	if apfb, ok := h.fallbacks[""]; ok {
		if pfb, ok := apfb[alpn]; ok {
			if fb, ok := pfb[path]; ok {
				return fb
			}
			if fb, ok := pfb[""]; ok {
				return fb
			}
		}
		if pfb, ok := apfb[""]; ok {
			if fb, ok := pfb[path]; ok {
				return fb
			}
			if fb, ok := pfb[""]; ok {
				return fb
			}
		}
	}

	return nil
}

// handleFallback handles connections that are not Reflex protocol
func (h *Handler) handleFallback(ctx context.Context, reader *bufio.Reader, conn stat.Connection) error {
	// Peek to determine connection type
	peeked, err := reader.Peek(1024)
	if err != nil && err != io.EOF {
		newError("failed to peek for fallback: ", err).AtWarning()
		return err
	}

	var name, alpn, path string

	// Determine connection type and extract metadata
	if isTLSHandshake(peeked) {
		// TLS connection
		name = extractSNI(peeked)
		alpn = extractALPN(peeked)
		if alpn == "" {
			alpn = "tls" // Default ALPN for TLS without explicit ALPN
		}
		newError("fallback: TLS connection detected, SNI=", name, " ALPN=", alpn).AtInfo()
	} else if isHTTPRequest(peeked) {
		// HTTP connection
		name = extractHTTPHost(peeked)
		path = extractHTTPPath(peeked)
		alpn = "http/1.1" // Default for HTTP
		newError("fallback: HTTP connection detected, Host=", name, " Path=", path).AtInfo()
	} else {
		// Unknown protocol
		name = ""
		alpn = ""
		path = ""
		newError("fallback: unknown protocol").AtInfo()
	}

	// Find appropriate fallback
	fb := h.findFallback(name, alpn, path)
	if fb == nil {
		// Try default fallback
		fb = h.findFallback("", "", "")
	}

	if fb == nil {
		newError("no fallback configured, rejecting connection").AtWarning()
		conn.Close()
		return errors.New("no fallback configured")
	}

	newError("fallback: forwarding to ", fb.Dest).AtInfo()

	// Connect to fallback destination
	var dest string
	if strings.Contains(fb.Dest, ":") {
		dest = fb.Dest
	} else {
		// If only port is specified, connect to localhost
		dest = "127.0.0.1:" + fb.Dest
	}

	// If dest is just a number, treat as port
	if _, err := strconv.Atoi(fb.Dest); err == nil {
		dest = "127.0.0.1:" + fb.Dest
	}

	targetConn, err := net.Dial("tcp", dest)
	if err != nil {
		newError("failed to connect to fallback destination: ", err).AtError()
		return errors.New("failed to connect to fallback").Base(err)
	}
	defer targetConn.Close()

	// Create wrapped connection that preserves peeked bytes
	wrappedConn := newPreloadedConn(reader, conn)

	// Bidirectional copy
	errChan := make(chan error, 2)

	go func() {
		_, err := io.Copy(targetConn, wrappedConn)
		errChan <- err
	}()

	go func() {
		_, err := io.Copy(wrappedConn, targetConn)
		errChan <- err
	}()

	// Wait for either direction to complete
	err = <-errChan

	if err != nil && err != io.EOF {
		newError("fallback copy error: ", err).AtInfo()
	}

	return nil
}

// handleTLSFallback handles TLS connections with SNI-based routing
func (h *Handler) handleTLSFallback(ctx context.Context, reader *bufio.Reader, conn stat.Connection, sni, alpn string) error {
	fb := h.findFallback(sni, alpn, "")
	if fb == nil {
		fb = h.findFallback("", alpn, "")
	}
	if fb == nil {
		fb = h.findFallback("", "", "")
	}

	if fb == nil {
		return errors.New("no TLS fallback configured")
	}

	return h.forwardToFallback(ctx, reader, conn, fb.Dest)
}

// handleHTTPFallback handles HTTP connections with Host/Path-based routing
func (h *Handler) handleHTTPFallback(ctx context.Context, reader *bufio.Reader, conn stat.Connection, host, path string) error {
	fb := h.findFallback(host, "http/1.1", path)
	if fb == nil {
		fb = h.findFallback(host, "http/1.1", "")
	}
	if fb == nil {
		fb = h.findFallback("", "http/1.1", path)
	}
	if fb == nil {
		fb = h.findFallback("", "http/1.1", "")
	}
	if fb == nil {
		fb = h.findFallback("", "", "")
	}

	if fb == nil {
		return errors.New("no HTTP fallback configured")
	}

	return h.forwardToFallback(ctx, reader, conn, fb.Dest)
}

// forwardToFallback forwards the connection to the fallback destination
func (h *Handler) forwardToFallback(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dest string) error {
	targetConn, err := net.Dial("tcp", dest)
	if err != nil {
		return errors.New("failed to connect to fallback").Base(err)
	}
	defer targetConn.Close()

	wrappedConn := newPreloadedConn(reader, conn)

	// Bidirectional copy
	errChan := make(chan error, 2)

	go func() {
		_, err := io.Copy(targetConn, wrappedConn)
		errChan <- err
	}()

	go func() {
		_, err := io.Copy(wrappedConn, targetConn)
		errChan <- err
	}()

	return <-errChan
}

// Helper to check if TLS version is supported
func isSupportedTLSVersion(version uint16) bool {
	switch version {
	case tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12, tls.VersionTLS13:
		return true
	default:
		return false
	}
}
