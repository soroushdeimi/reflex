package codec

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"strconv"
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/proxy/reflex/handshake"
)

// HTTPOptions controls how we format the HTTP-like request.
// Host and Path are used only for writing (client side).
type HTTPOptions struct {
	Method string
	Path   string
	Host   string
}

func DefaultHTTPOptions(host string) HTTPOptions {
	return HTTPOptions{
		Method: "POST",
		Path:   "/api/v1/endpoint",
		Host:   host,
	}
}

type httpBody struct {
	Data string `json:"data"`
}

// ReadHTTPClientHandshake parses a POST-like HTTP request with JSON body:
// { "data": "<base64 payload>" }
//
// The payload is the canonical binary client handshake WITHOUT magic:
//
//	pubkey(32) | userid(16) | timestamp(8) | nonce(16) | policyLen(2) | policyReq(policyLen)
func ReadHTTPClientHandshake(r *bufio.Reader) (*handshake.ClientHandshake, error) {
	if r == nil {
		return nil, handshake.New(handshake.KindInternal, "nil reader")
	}

	headerBytes, err := readHTTPHeaders(r, handshake.MaxHTTPHeaderBytes)
	if err != nil {
		// could be not-http traffic
		return nil, err
	}

	method, _, _, headers, err := parseHTTPHeaders(headerBytes)
	if err != nil {
		return nil, err
	}

	if method != "POST" {
		return nil, handshake.New(handshake.KindInvalidHandshake, "method not POST")
	}

	cl, ok := headers["content-length"]
	if !ok {
		return nil, handshake.New(handshake.KindInvalidHandshake, "missing content-length")
	}

	n, err := strconv.Atoi(cl)
	if err != nil || n < 0 {
		return nil, handshake.New(handshake.KindInvalidHandshake, "invalid content-length")
	}
	if n > handshake.MaxHTTPBodyBytes {
		return nil, handshake.New(handshake.KindInvalidHandshake, "http body too large")
	}

	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, handshake.Wrap(handshake.KindInvalidHandshake, "read http body", err)
	}

	var hb httpBody

	if err := json.Unmarshal(body, &hb); err != nil {
		return nil, handshake.Wrap(handshake.KindInvalidHandshake, "invalid json body", err)
	}
	if strings.TrimSpace(hb.Data) == "" {
		return nil, handshake.New(handshake.KindInvalidHandshake, "missing data field")
	}

	payload, err := decodeBase64Any(hb.Data)
	if err != nil {
		return nil, handshake.Wrap(handshake.KindInvalidHandshake, "base64 decode data", err)
	}

	hs, err := parseClientPayload(payload)
	if err != nil {
		return nil, err
	}
	return hs, nil
}

// WriteHTTPClientHandshake writes an HTTP-like POST request with JSON body.
// Body: { "data": "<base64 payload>" }
func WriteHTTPClientHandshake(w io.Writer, hs *handshake.ClientHandshake, opt HTTPOptions) error {
	if w == nil {
		return handshake.New(handshake.KindInternal, "nil writer")
	}
	if hs == nil {
		return errors.New("reflex codec: nil client handshake")
	}
	if opt.Method == "" {
		opt.Method = "POST"
	}
	if opt.Path == "" {
		opt.Path = "/api/v1/endpoint"
	}
	if opt.Host == "" {
		opt.Host = "example.com"
	}

	payload, err := marshalClientPayload(hs)
	if err != nil {
		return err
	}

	hb := httpBody{
		Data: base64.StdEncoding.EncodeToString(payload),
	}
	body, err := json.Marshal(hb)
	if err != nil {
		return handshake.Wrap(handshake.KindInternal, "json marshal", err)
	}

	var b bytes.Buffer
	b.WriteString(opt.Method)
	b.WriteString(" ")
	b.WriteString(opt.Path)
	b.WriteString(" HTTP/1.1\r\n")
	b.WriteString("Host: ")
	b.WriteString(opt.Host)
	b.WriteString("\r\n")
	b.WriteString("Content-Type: application/json\r\n")
	b.WriteString("Content-Length: ")
	b.WriteString(strconv.Itoa(len(body)))
	b.WriteString("\r\n\r\n")
	b.Write(body)

	if _, err := w.Write(b.Bytes()); err != nil {
		return handshake.Wrap(handshake.KindInternal, "write http request", err)
	}
	return nil
}

// ReadHTTPServerHandshake parses an HTTP-like response with JSON body:
// { "data": "<base64 payload>" }
//
// Payload is canonical server handshake:
//
//	pubkey(32) | grantLen(2) | policyGrant(grantLen)
func ReadHTTPServerHandshake(r *bufio.Reader) (*handshake.ServerHandshake, error) {
	if r == nil {
		return nil, handshake.New(handshake.KindInternal, "nil reader")
	}

	headerBytes, err := readHTTPHeaders(r, handshake.MaxHTTPHeaderBytes)
	if err != nil {
		return nil, err
	}

	_, statusCode, headers, err := parseHTTPResponseHeaders(headerBytes)
	if err != nil {
		return nil, err
	}
	if statusCode < 200 || statusCode >= 300 {
		// Keep it as unauth/invalid for later. Caller can decide.
		return nil, handshake.New(handshake.KindUnauthenticated, "non-2xx http response")
	}

	cl, ok := headers["content-length"]
	if !ok {
		return nil, handshake.New(handshake.KindInvalidHandshake, "missing content-length")
	}
	n, err := strconv.Atoi(cl)
	if err != nil || n < 0 {
		return nil, handshake.New(handshake.KindInvalidHandshake, "invalid content-length")
	}
	if n > handshake.MaxHTTPBodyBytes {
		return nil, handshake.New(handshake.KindInvalidHandshake, "http body too large")
	}

	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, handshake.Wrap(handshake.KindInvalidHandshake, "read http body", err)
	}

	var hb httpBody
	if err := json.Unmarshal(body, &hb); err != nil {
		return nil, handshake.Wrap(handshake.KindInvalidHandshake, "invalid json body", err)
	}
	if strings.TrimSpace(hb.Data) == "" {
		return nil, handshake.New(handshake.KindInvalidHandshake, "missing data field")
	}

	payload, err := decodeBase64Any(hb.Data)
	if err != nil {
		return nil, handshake.Wrap(handshake.KindInvalidHandshake, "base64 decode data", err)
	}

	hs, err := parseServerPayload(payload)
	if err != nil {
		return nil, err
	}
	return hs, nil
}

// WriteHTTPServerHandshake writes an HTTP-like 200 response with JSON body:
// { "data": "<base64 payload>" }
func WriteHTTPServerHandshake(w io.Writer, hs *handshake.ServerHandshake) error {
	if w == nil {
		return handshake.New(handshake.KindInternal, "nil writer")
	}
	if hs == nil {
		return errors.New("reflex codec: nil server handshake")
	}

	payload, err := marshalServerPayload(hs)
	if err != nil {
		return err
	}

	hb := httpBody{Data: base64.StdEncoding.EncodeToString(payload)}
	body, err := json.Marshal(hb)
	if err != nil {
		return handshake.Wrap(handshake.KindInternal, "json marshal", err)
	}

	var b bytes.Buffer
	b.WriteString("HTTP/1.1 200 OK\r\n")
	b.WriteString("Content-Type: application/json\r\n")
	b.WriteString("Content-Length: ")
	b.WriteString(strconv.Itoa(len(body)))
	b.WriteString("\r\n\r\n")
	b.Write(body)

	if _, err := w.Write(b.Bytes()); err != nil {
		return handshake.Wrap(handshake.KindInternal, "write http response", err)
	}
	return nil
}

// ---- helpers ----

// readHTTPHeaders reads until "\r\n\r\n" with a maximum cap.
// It returns the raw header bytes including the ending "\r\n\r\n".
func readHTTPHeaders(r *bufio.Reader, max int) ([]byte, error) {
	var buf bytes.Buffer
	buf.Grow(1024)

	// scan byte-by-byte (max is small: 8KB), safe and simple.
	var last4 [4]byte
	n := 0
	for n < max {
		b, err := r.ReadByte()
		if err != nil {
			return nil, handshake.Wrap(handshake.KindInvalidHandshake, "read http header", err)
		}
		_ = buf.WriteByte(b)

		last4[0], last4[1], last4[2], last4[3] = last4[1], last4[2], last4[3], b
		n++
		if last4 == [4]byte{'\r', '\n', '\r', '\n'} {
			return buf.Bytes(), nil
		}
	}
	return nil, handshake.New(handshake.KindInvalidHandshake, "http header too large")
}

func parseHTTPHeaders(headerBytes []byte) (method, path, version string, headers map[string]string, err error) {
	// headerBytes ends with \r\n\r\n
	s := string(headerBytes)
	lines := strings.Split(s, "\r\n")
	if len(lines) < 2 {
		return "", "", "", nil, handshake.New(handshake.KindInvalidHandshake, "not http-like")
	}

	// Request line: METHOD SP PATH SP HTTP/1.1
	parts := strings.Split(lines[0], " ")
	if len(parts) < 3 {
		return "", "", "", nil, handshake.New(handshake.KindInvalidHandshake, "invalid request line")
	}
	method = strings.ToUpper(strings.TrimSpace(parts[0]))
	path = strings.TrimSpace(parts[1])
	version = strings.TrimSpace(parts[2])

	h := make(map[string]string, 8)
	for _, ln := range lines[1:] {
		if ln == "" {
			break
		}
		i := strings.Index(ln, ":")
		if i <= 0 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(ln[:i]))
		v := strings.TrimSpace(ln[i+1:])
		h[k] = v
	}
	return method, path, version, h, nil
}

func parseHTTPResponseHeaders(headerBytes []byte) (version string, statusCode int, headers map[string]string, err error) {
	s := string(headerBytes)
	lines := strings.Split(s, "\r\n")
	if len(lines) < 2 {
		return "", 0, nil, handshake.New(handshake.KindInvalidHandshake, "invalid http response")
	}

	// Status line: HTTP/1.1 200 OK
	parts := strings.Split(lines[0], " ")
	if len(parts) < 2 {
		return "", 0, nil, handshake.New(handshake.KindInvalidHandshake, "invalid status line")
	}
	version = strings.TrimSpace(parts[0])
	code, e := strconv.Atoi(strings.TrimSpace(parts[1]))
	if e != nil {
		return "", 0, nil, handshake.New(handshake.KindInvalidHandshake, "invalid status code")
	}

	h := make(map[string]string, 8)
	for _, ln := range lines[1:] {
		if ln == "" {
			break
		}
		i := strings.Index(ln, ":")
		if i <= 0 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(ln[:i]))
		v := strings.TrimSpace(ln[i+1:])
		h[k] = v
	}
	return version, code, h, nil
}

func decodeBase64Any(s string) ([]byte, error) {
	// Remove surrounding spaces/newlines
	s = strings.TrimSpace(s)

	// Try Std, RawStd, URL variants
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return nil, errors.New("invalid base64")
}

func parseClientPayload(payload []byte) (*handshake.ClientHandshake, error) {
	// pubkey(32) | userid(16) | timestamp(8) | nonce(16) | policyLen(2) | policyReq
	min := handshake.PublicKeySize + handshake.UserIDSize + 8 + handshake.NonceSize + 2
	if len(payload) < min {
		return nil, handshake.New(handshake.KindInvalidHandshake, "client payload too short")
	}

	r := bytes.NewReader(payload)
	var hs handshake.ClientHandshake

	if _, err := io.ReadFull(r, hs.PublicKey[:]); err != nil {
		return nil, handshake.Wrap(handshake.KindInvalidHandshake, "read client public key", err)
	}
	if _, err := io.ReadFull(r, hs.UserID[:]); err != nil {
		return nil, handshake.Wrap(handshake.KindInvalidHandshake, "read user id", err)
	}

	var tsBuf [8]byte
	if _, err := io.ReadFull(r, tsBuf[:]); err != nil {
		return nil, handshake.Wrap(handshake.KindInvalidHandshake, "read timestamp", err)
	}
	hs.Timestamp = int64(binary.BigEndian.Uint64(tsBuf[:]))

	if _, err := io.ReadFull(r, hs.Nonce[:]); err != nil {
		return nil, handshake.Wrap(handshake.KindInvalidHandshake, "read nonce", err)
	}

	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, handshake.Wrap(handshake.KindInvalidHandshake, "read policy length", err)
	}
	policyLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if policyLen < 0 || policyLen > handshake.MaxPolicyReqSize {
		return nil, handshake.New(handshake.KindInvalidHandshake, "policy request too large")
	}

	rest := make([]byte, policyLen)
	if policyLen > 0 {
		if _, err := io.ReadFull(r, rest); err != nil {
			return nil, handshake.Wrap(handshake.KindInvalidHandshake, "read policy request", err)
		}
	}
	hs.PolicyReq = rest

	// Extra trailing bytes are ignored for forward-compatibility.
	return &hs, nil
}

func marshalClientPayload(hs *handshake.ClientHandshake) ([]byte, error) {
	if len(hs.PolicyReq) > handshake.MaxPolicyReqSize {
		return nil, handshake.New(handshake.KindInvalidHandshake, "policy request too large")
	}
	if len(hs.PolicyReq) > 0xFFFF {
		return nil, handshake.New(handshake.KindInvalidHandshake, "policy request length overflow")
	}

	var b bytes.Buffer
	b.Grow(handshake.PublicKeySize + handshake.UserIDSize + 8 + handshake.NonceSize + 2 + len(hs.PolicyReq))

	_, _ = b.Write(hs.PublicKey[:])
	_, _ = b.Write(hs.UserID[:])

	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], uint64(hs.Timestamp))
	_, _ = b.Write(tsBuf[:])

	_, _ = b.Write(hs.Nonce[:])

	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(hs.PolicyReq)))
	_, _ = b.Write(lenBuf[:])

	if len(hs.PolicyReq) > 0 {
		_, _ = b.Write(hs.PolicyReq)
	}

	return b.Bytes(), nil
}

func parseServerPayload(payload []byte) (*handshake.ServerHandshake, error) {
	min := handshake.PublicKeySize + 2
	if len(payload) < min {
		return nil, handshake.New(handshake.KindInvalidHandshake, "server payload too short")
	}

	r := bytes.NewReader(payload)
	var hs handshake.ServerHandshake

	if _, err := io.ReadFull(r, hs.PublicKey[:]); err != nil {
		return nil, handshake.Wrap(handshake.KindInvalidHandshake, "read server public key", err)
	}

	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, handshake.Wrap(handshake.KindInvalidHandshake, "read grant length", err)
	}
	grantLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if grantLen < 0 || grantLen > handshake.MaxPolicyGrantSize {
		return nil, handshake.New(handshake.KindInvalidHandshake, "policy grant too large")
	}

	if grantLen > 0 {
		hs.PolicyGrant = make([]byte, grantLen)
		if _, err := io.ReadFull(r, hs.PolicyGrant); err != nil {
			return nil, handshake.Wrap(handshake.KindInvalidHandshake, "read policy grant", err)
		}
	} else {
		hs.PolicyGrant = nil
	}

	// Extra trailing bytes ignored.
	return &hs, nil
}

func marshalServerPayload(hs *handshake.ServerHandshake) ([]byte, error) {
	if len(hs.PolicyGrant) > handshake.MaxPolicyGrantSize {
		return nil, handshake.New(handshake.KindInvalidHandshake, "policy grant too large")
	}
	if len(hs.PolicyGrant) > 0xFFFF {
		return nil, handshake.New(handshake.KindInvalidHandshake, "policy grant length overflow")
	}

	var b bytes.Buffer
	b.Grow(handshake.PublicKeySize + 2 + len(hs.PolicyGrant))

	_, _ = b.Write(hs.PublicKey[:])

	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(hs.PolicyGrant)))
	_, _ = b.Write(lenBuf[:])

	if len(hs.PolicyGrant) > 0 {
		_, _ = b.Write(hs.PolicyGrant)
	}

	return b.Bytes(), nil
}
