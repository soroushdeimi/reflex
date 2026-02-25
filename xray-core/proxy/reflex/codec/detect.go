package codec

import "bytes"

const reflexHTTPPath = "/api/v1/endpoint"

// LooksLikeHTTPPost returns true ONLY if peeked bytes resemble Reflex's HTTP-like handshake.
// It is intentionally conservative: if unsure, return false so Step4 fallback can handle.
// We do NOT want to match generic HTTP POSTs, otherwise we may consume bytes and break fallback.
func LooksLikeHTTPPost(peeked []byte) bool {
	// Must start with "POST "
	if len(peeked) < len("POST ")+1 {
		return false
	}
	if !bytes.HasPrefix(peeked, []byte("POST ")) {
		return false
	}

	// We only peek a small prefix; parse the request line from it.
	// Request line example:
	// POST /api/v1/endpoint HTTP/1.1\r\n
	lineEnd := bytes.Index(peeked, []byte("\r\n"))
	if lineEnd < 0 {
		return false
	}
	line := peeked[:lineEnd]

	// Extract path: after "POST " until next space.
	rest := line[len("POST "):]
	sp := bytes.IndexByte(rest, ' ')
	if sp <= 0 {
		return false
	}
	path := rest[:sp]
	if !bytes.Equal(path, []byte(reflexHTTPPath)) {
		return false
	}

	// Must mention HTTP/1.x in request line.
	if !bytes.Contains(rest[sp+1:], []byte("HTTP/1.")) {
		return false
	}

	return true
}
