package reflex

import (
	"bufio"
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const (
	// ReflexMagic is the 4-byte magic prefix for the binary handshake.
	ReflexMagic uint32 = 0x5246584c // "RFXL"

	// Minimum bytes to peek to decide handshake type.
	MinHandshakePeek = 64

	// DefaultHandshakePath is used by the HTTP-like handshake encoder.
	DefaultHandshakePath = "/api/v1/status"
)

// ClientHandshake is sent by the client as the first message.
type ClientHandshake struct {
	ClientPubKey [32]byte
	UserID       [16]byte
	Timestamp    int64
	Nonce        [16]byte
	// PolicyReq is encrypted with a UUID-derived PSK (see step2 docs).
	PolicyReq []byte
}

// ServerHandshake is the HTTP-like 200 OK response containing server pubkey and policy grant.
type ServerHandshake struct {
	ServerPubKey [32]byte
	// PolicyGrant is encrypted with the same UUID-derived PSK.
	PolicyGrant []byte
}

// GenerateKeyPair creates an X25519 keypair.
func GenerateKeyPair() (priv [32]byte, pub [32]byte, err error) {
	curve := ecdh.X25519()
	k, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return priv, pub, err
	}
	copy(priv[:], k.Bytes())
	copy(pub[:], k.PublicKey().Bytes())
	return priv, pub, nil
}

// DeriveSharedSecret computes X25519(private, peerPublic).
func DeriveSharedSecret(priv [32]byte, peerPub [32]byte) ([32]byte, error) {
	var out [32]byte
	curve := ecdh.X25519()
	privKey, err := curve.NewPrivateKey(priv[:])
	if err != nil {
		return out, fmt.Errorf("invalid private key: %w", err)
	}
	pubKey, err := curve.NewPublicKey(peerPub[:])
	if err != nil {
		return out, fmt.Errorf("invalid peer public key: %w", err)
	}
	ss, err := privKey.ECDH(pubKey)
	if err != nil {
		return out, err
	}
	copy(out[:], ss)
	return out, nil
}

// DeriveSessionKey derives a 32-byte session key from shared secret and salt.
//
// We use HKDF-SHA256(sharedSecret, salt=clientNonce, info="reflex-session").
func DeriveSessionKey(sharedSecret [32]byte, salt []byte) [32]byte {
	okm := HKDFSHA256(sharedSecret[:], salt, []byte("reflex-session"), 32)
	var key [32]byte
	copy(key[:], okm)
	return key
}

// EncodeClientHandshakeMagic encodes a binary handshake with a 4-byte magic prefix.
func EncodeClientHandshakeMagic(h ClientHandshake) []byte {
	buf := bytes.NewBuffer(make([]byte, 0, 4+32+16+8+16+2+len(h.PolicyReq)))
	_ = binary.Write(buf, binary.BigEndian, ReflexMagic)
	buf.Write(h.ClientPubKey[:])
	buf.Write(h.UserID[:])
	_ = binary.Write(buf, binary.BigEndian, h.Timestamp)
	buf.Write(h.Nonce[:])
	_ = binary.Write(buf, binary.BigEndian, uint16(len(h.PolicyReq)))
	buf.Write(h.PolicyReq)
	return buf.Bytes()
}

// ReadClientHandshakeMagic reads a magic-prefixed handshake from r.
func ReadClientHandshakeMagic(r io.Reader) (ClientHandshake, error) {
	var h ClientHandshake
	var magic uint32
	if err := binary.Read(r, binary.BigEndian, &magic); err != nil {
		return h, err
	}
	if magic != ReflexMagic {
		return h, fmt.Errorf("invalid magic")
	}
	if _, err := io.ReadFull(r, h.ClientPubKey[:]); err != nil {
		return h, err
	}
	if _, err := io.ReadFull(r, h.UserID[:]); err != nil {
		return h, err
	}
	if err := binary.Read(r, binary.BigEndian, &h.Timestamp); err != nil {
		return h, err
	}
	if _, err := io.ReadFull(r, h.Nonce[:]); err != nil {
		return h, err
	}
	var l uint16
	if err := binary.Read(r, binary.BigEndian, &l); err != nil {
		return h, err
	}
	if l > 0 {
		h.PolicyReq = make([]byte, int(l))
		if _, err := io.ReadFull(r, h.PolicyReq); err != nil {
			return h, err
		}
	}
	return h, nil
}

// EncodeServerHandshake encodes server handshake bytes (binary, no magic).
func EncodeServerHandshake(h ServerHandshake) []byte {
	buf := bytes.NewBuffer(make([]byte, 0, 32+2+len(h.PolicyGrant)))
	buf.Write(h.ServerPubKey[:])
	_ = binary.Write(buf, binary.BigEndian, uint16(len(h.PolicyGrant)))
	buf.Write(h.PolicyGrant)
	return buf.Bytes()
}

// DecodeServerHandshake decodes server handshake bytes.
func DecodeServerHandshake(b []byte) (ServerHandshake, error) {
	var h ServerHandshake
	r := bytes.NewReader(b)
	if _, err := io.ReadFull(r, h.ServerPubKey[:]); err != nil {
		return h, err
	}
	var l uint16
	if err := binary.Read(r, binary.BigEndian, &l); err != nil {
		return h, err
	}
	if l > 0 {
		h.PolicyGrant = make([]byte, int(l))
		if _, err := io.ReadFull(r, h.PolicyGrant); err != nil {
			return h, err
		}
	}
	return h, nil
}

// httpEnvelope is the JSON envelope used by the HTTP-like handshake.
//
// {"data": "base64..."}
type httpEnvelope struct {
	Data string `json:"data"`
}

// EncodeClientHandshakeHTTP builds an HTTP POST-like request that carries the handshake in JSON.
func EncodeClientHandshakeHTTP(h ClientHandshake, host, path string) []byte {
	if path == "" {
		path = DefaultHandshakePath
	}
	payload := EncodeClientHandshakeMagic(h)
	// For HTTP mode we reuse the binary handshake but without requiring the peer to check magic.
	// The server may still accept it.
	enc := base64.StdEncoding.EncodeToString(payload)
	body, _ := json.Marshal(httpEnvelope{Data: enc})
	req := bytes.NewBuffer(nil)
	fmt.Fprintf(req, "POST %s HTTP/1.1\r\n", path)
	if host == "" {
		host = "example.com"
	}
	fmt.Fprintf(req, "Host: %s\r\n", host)
	fmt.Fprintf(req, "Content-Type: application/json\r\n")
	fmt.Fprintf(req, "Content-Length: %d\r\n", len(body))
	fmt.Fprintf(req, "\r\n")
	req.Write(body)
	return req.Bytes()
}

// ReadClientHandshakeHTTP parses an HTTP request from reader and extracts the handshake.
func ReadClientHandshakeHTTP(reader *bufio.Reader) (ClientHandshake, error) {
	var h ClientHandshake
	// Read request line
	line, err := reader.ReadString('\n')
	if err != nil {
		return h, err
	}
	if !strings.HasPrefix(line, "POST ") {
		return h, errors.New("not a POST request")
	}
	// Read headers
	var contentLen int
	for {
		hdr, err := reader.ReadString('\n')
		if err != nil {
			return h, err
		}
		hdr = strings.TrimRight(hdr, "\r\n")
		if hdr == "" {
			break
		}
		parts := strings.SplitN(hdr, ":", 2)
		if len(parts) != 2 {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(parts[0]))
		value := strings.TrimSpace(parts[1])
		if name == "content-length" {
			if _, scanErr := fmt.Sscanf(value, "%d", &contentLen); scanErr != nil {
				return h, fmt.Errorf("invalid content-length: %w", scanErr)
			}
		}
	}
	if contentLen <= 0 || contentLen > 1<<20 {
		return h, fmt.Errorf("invalid content-length")
	}
	body := make([]byte, contentLen)
	if _, err := io.ReadFull(reader, body); err != nil {
		return h, err
	}
	var env httpEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return h, err
	}
	decoded, err := base64.StdEncoding.DecodeString(env.Data)
	if err != nil {
		return h, err
	}
	// We accept either magic-prefixed or raw handshake. If it starts with magic, use the magic reader.
	if len(decoded) >= 4 && binary.BigEndian.Uint32(decoded[:4]) == ReflexMagic {
		return ReadClientHandshakeMagic(bytes.NewReader(decoded))
	}
	// Otherwise, parse as raw: pub(32)+user(16)+ts(8)+nonce(16)+len(2)+policy
	r := bytes.NewReader(decoded)
	if _, err := io.ReadFull(r, h.ClientPubKey[:]); err != nil {
		return h, err
	}
	if _, err := io.ReadFull(r, h.UserID[:]); err != nil {
		return h, err
	}
	if err := binary.Read(r, binary.BigEndian, &h.Timestamp); err != nil {
		return h, err
	}
	if _, err := io.ReadFull(r, h.Nonce[:]); err != nil {
		return h, err
	}
	var l uint16
	if err := binary.Read(r, binary.BigEndian, &l); err != nil {
		return h, err
	}
	if l > 0 {
		h.PolicyReq = make([]byte, int(l))
		if _, err := io.ReadFull(r, h.PolicyReq); err != nil {
			return h, err
		}
	}
	return h, nil
}

// ReadClientHandshakeHTTPWithRaw parses an HTTP request from reader and extracts the handshake.
//
// It also returns the exact bytes consumed from the reader (request line + headers + body).
// This is critical for robust fallback: if the traffic is NOT a Reflex handshake (e.g., it is a normal
// HTTP request that merely starts with "POST"), the caller can forward these raw bytes to the
// fallback web server so the original request is not corrupted.
func ReadClientHandshakeHTTPWithRaw(reader *bufio.Reader) (ClientHandshake, []byte, error) {
	var h ClientHandshake
	var raw bytes.Buffer

	// Read request line
	line, err := reader.ReadString('\n')
	if err != nil {
		return h, raw.Bytes(), err
	}
	raw.WriteString(line)

	if !strings.HasPrefix(line, "POST ") {
		return h, raw.Bytes(), errors.New("not a POST request")
	}

	// Read headers
	var contentLen int
	for {
		hdrLine, err := reader.ReadString('\n')
		if err != nil {
			return h, raw.Bytes(), err
		}
		raw.WriteString(hdrLine)

		hdr := strings.TrimRight(hdrLine, "\r\n")
		if hdr == "" {
			break
		}
		parts := strings.SplitN(hdr, ":", 2)
		if len(parts) != 2 {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(parts[0]))
		value := strings.TrimSpace(parts[1])
		if name == "content-length" {
			if _, scanErr := fmt.Sscanf(value, "%d", &contentLen); scanErr != nil {
				return h, raw.Bytes(), fmt.Errorf("invalid content-length: %w", scanErr)
			}
		}
	}

	if contentLen <= 0 || contentLen > 1<<20 {
		return h, raw.Bytes(), fmt.Errorf("invalid content-length")
	}

	// Read body
	body := make([]byte, contentLen)
	n, err := io.ReadFull(reader, body)
	if n > 0 {
		raw.Write(body[:n])
	}
	if err != nil {
		return h, raw.Bytes(), err
	}

	// Parse JSON envelope
	var env httpEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return h, raw.Bytes(), err
	}
	decoded, err := base64.StdEncoding.DecodeString(env.Data)
	if err != nil {
		return h, raw.Bytes(), err
	}

	// We accept either magic-prefixed or raw handshake.
	if len(decoded) >= 4 && binary.BigEndian.Uint32(decoded[:4]) == ReflexMagic {
		hh, err := ReadClientHandshakeMagic(bytes.NewReader(decoded))
		return hh, raw.Bytes(), err
	}

	// Otherwise parse as raw: pub(32)+user(16)+ts(8)+nonce(16)+len(2)+policy
	r := bytes.NewReader(decoded)
	if _, err := io.ReadFull(r, h.ClientPubKey[:]); err != nil {
		return h, raw.Bytes(), err
	}
	if _, err := io.ReadFull(r, h.UserID[:]); err != nil {
		return h, raw.Bytes(), err
	}
	if err := binary.Read(r, binary.BigEndian, &h.Timestamp); err != nil {
		return h, raw.Bytes(), err
	}
	if _, err := io.ReadFull(r, h.Nonce[:]); err != nil {
		return h, raw.Bytes(), err
	}
	var l uint16
	if err := binary.Read(r, binary.BigEndian, &l); err != nil {
		return h, raw.Bytes(), err
	}
	if l > 0 {
		h.PolicyReq = make([]byte, int(l))
		if _, err := io.ReadFull(r, h.PolicyReq); err != nil {
			return h, raw.Bytes(), err
		}
	}

	return h, raw.Bytes(), nil
}

// EncodeServerHandshakeHTTP builds an HTTP 200 OK response carrying the server handshake.
func EncodeServerHandshakeHTTP(h ServerHandshake) []byte {
	b := EncodeServerHandshake(h)
	enc := base64.StdEncoding.EncodeToString(b)
	body, _ := json.Marshal(httpEnvelope{Data: enc})
	resp := bytes.NewBuffer(nil)
	fmt.Fprintf(resp, "HTTP/1.1 200 OK\r\n")
	fmt.Fprintf(resp, "Content-Type: application/json\r\n")
	fmt.Fprintf(resp, "Content-Length: %d\r\n", len(body))
	fmt.Fprintf(resp, "\r\n")
	resp.Write(body)
	return resp.Bytes()
}

// ReadServerHandshakeHTTP reads an HTTP response from reader and extracts the server handshake.
func ReadServerHandshakeHTTP(reader *bufio.Reader) (ServerHandshake, error) {
	var h ServerHandshake
	// Status line
	line, err := reader.ReadString('\n')
	if err != nil {
		return h, err
	}
	if !strings.HasPrefix(line, "HTTP/1.1 200") {
		return h, fmt.Errorf("unexpected response: %s", strings.TrimSpace(line))
	}
	var contentLen int
	for {
		hdr, err := reader.ReadString('\n')
		if err != nil {
			return h, err
		}
		hdr = strings.TrimRight(hdr, "\r\n")
		if hdr == "" {
			break
		}
		parts := strings.SplitN(hdr, ":", 2)
		if len(parts) != 2 {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(parts[0]))
		value := strings.TrimSpace(parts[1])
		if name == "content-length" {
			if _, scanErr := fmt.Sscanf(value, "%d", &contentLen); scanErr != nil {
				return h, fmt.Errorf("invalid content-length: %w", scanErr)
			}
		}
	}
	if contentLen <= 0 || contentLen > 1<<20 {
		return h, fmt.Errorf("invalid content-length")
	}
	body := make([]byte, contentLen)
	if _, err := io.ReadFull(reader, body); err != nil {
		return h, err
	}
	var env httpEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return h, err
	}
	decoded, err := base64.StdEncoding.DecodeString(env.Data)
	if err != nil {
		return h, err
	}
	return DecodeServerHandshake(decoded)
}

// NewClientHandshake builds a fresh client handshake with random nonce and current timestamp.
func NewClientHandshake(clientPub [32]byte, userID [16]byte, policyReq []byte) (ClientHandshake, error) {
	var h ClientHandshake
	h.ClientPubKey = clientPub
	h.UserID = userID
	h.Timestamp = time.Now().Unix()
	if _, err := rand.Read(h.Nonce[:]); err != nil {
		return h, err
	}
	h.PolicyReq = policyReq
	return h, nil
}
