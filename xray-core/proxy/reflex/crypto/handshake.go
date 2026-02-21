package crypto

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/reflex/session"
)

const ReflexMagic = 0x5246584C // "REFX"

// ClientHandshake represents the raw handshake structure sent by the client.
type ClientHandshake struct {
	PublicKey [32]byte
	UserID    [16]byte
	PolicyReq []byte
	Timestamp int64
	Nonce     [16]byte
}

// ServerHello represents the handshake response returned to the client.
type ServerHello struct {
	PublicKey   [32]byte `json:"public_key"`
	PolicyGrant []byte   `json:"policy_grant"`
}

// Handshake-level replay cache.
var (
	nonceCache = make(map[[16]byte]int64)
	nonceMutex sync.Mutex
)

// generateKeyPair creates an ephemeral X25519 key pair.
func generateKeyPair() (privateKey [32]byte, publicKey [32]byte) {
	rand.Read(privateKey[:])
	curve25519.ScalarBaseMult(&publicKey, &privateKey)
	return
}

// derivePreSharedKey derives a simple pre-shared key from the client UUID.
func derivePreSharedKey(userID [16]byte) []byte {
	h := sha256.Sum256(userID[:])
	return h[:]
}

// deriveSharedKey computes the X25519 shared secret.
func deriveSharedKey(privateKey, peerPublicKey [32]byte) [32]byte {
	var shared [32]byte
	curve25519.ScalarMult(&shared, &privateKey, &peerPublicKey)
	return shared
}

// deriveSessionKey derives a 32-byte session key using HKDF-SHA256.
func deriveSessionKey(sharedKey [32]byte) []byte {
	h := hkdf.New(sha256.New, sharedKey[:], nil, []byte("reflex-session"))
	key := make([]byte, 32)
	io.ReadFull(h, key)
	return key
}

// authenticateUserBytes validates the UUID against configured users.
func authenticateUserBytes(userID [16]byte, clients []*protocol.MemoryUser) (*protocol.MemoryUser, error) {
	uid := uuid.UUID(userID).String()
	for _, user := range clients {
		if user.Email == uid {
			return user, nil
		}
	}
	return nil, errors.New("user not found")
}

// checkReplay ensures a nonce has not been reused.
func checkReplay(nonce [16]byte) error {
	nonceMutex.Lock()
	defer nonceMutex.Unlock()

	if _, exists := nonceCache[nonce]; exists {
		return errors.New("replay detected")
	}

	nonceCache[nonce] = time.Now().Unix()
	return nil
}

// decryptPolicy performs simple XOR-based policy decoding.
// (Placeholder logic for Step 2; will be replaced in Step 3+.)
func decryptPolicy(policy []byte, key []byte) []byte {
	out := make([]byte, len(policy))
	for i := range policy {
		out[i] = policy[i] ^ key[i%len(key)]
	}
	return out
}

// writeHTTPError sends a structured HTTP-style error response.
func writeHTTPError(conn net.Conn, code int, msg string) {
	response := fmt.Sprintf(
		"HTTP/1.1 %d %s\r\nContent-Type: application/json\r\n\r\n{\"error\":\"%s\"}",
		code,
		httpStatusText(code),
		msg,
	)
	conn.Write([]byte(response))
}

func httpStatusText(code int) string {
	switch code {
	case 400:
		return "Bad Request"
	case 401:
		return "Unauthorized"
	case 403:
		return "Forbidden"
	default:
		return "Error"
	}
}

// ServerHandshake detects protocol format and processes the initial handshake.
// Supports both magic-prefixed and HTTP POST-like formats.
func ServerHandshake(reader *bufio.Reader, conn net.Conn, clients []*protocol.MemoryUser) (*session.Session, error) {

	peeked, err := reader.Peek(4)
	if err != nil {
		return nil, err
	}

	if binary.BigEndian.Uint32(peeked) == ReflexMagic {
		return handleMagic(reader, conn, clients)
	}

	if strings.HasPrefix(string(peeked), "POST") {
		return handleHTTP(reader, conn, clients)
	}

	return nil, errors.New("not reflex traffic")
}

// readClientHandshake parses the raw handshake structure from a reader.
func readClientHandshake(r io.Reader) (ClientHandshake, error) {
	var hs ClientHandshake

	if _, err := io.ReadFull(r, hs.PublicKey[:]); err != nil {
		return hs, err
	}

	if _, err := io.ReadFull(r, hs.UserID[:]); err != nil {
		return hs, err
	}

	var policyLen uint16
	if err := binary.Read(r, binary.BigEndian, &policyLen); err != nil {
		return hs, err
	}

	if policyLen > 4096 {
		return hs, errors.New("policy too large")
	}

	hs.PolicyReq = make([]byte, policyLen)
	if _, err := io.ReadFull(r, hs.PolicyReq); err != nil {
		return hs, err
	}

	if err := binary.Read(r, binary.BigEndian, &hs.Timestamp); err != nil {
		return hs, err
	}

	if _, err := io.ReadFull(r, hs.Nonce[:]); err != nil {
		return hs, err
	}

	return hs, nil
}

// handleMagic processes magic-prefixed handshake format.
func handleMagic(reader *bufio.Reader, conn net.Conn, clients []*protocol.MemoryUser) (*session.Session, error) {
	if _, err := io.ReadFull(reader, make([]byte, 4)); err != nil {
		return nil, err
	}

	hs, err := readClientHandshake(reader)
	if err != nil {
		return nil, err
	}

	return processHandshake(conn, clients, hs)
}

// handleHTTP processes HTTP POST-like handshake format.
func handleHTTP(reader *bufio.Reader, conn net.Conn, clients []*protocol.MemoryUser) (*session.Session, error) {

	var contentLength int

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}

		if strings.HasPrefix(strings.ToLower(line), "content-length:") {
			fmt.Sscanf(line, "Content-Length: %d", &contentLength)
		}

		if line == "\r\n" {
			break
		}
	}

	if contentLength <= 0 {
		return nil, errors.New("invalid content length")
	}

	body := make([]byte, contentLength)
	if _, err := io.ReadFull(reader, body); err != nil {
		return nil, err
	}

	var parsed map[string]string
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, err
	}

	raw, err := base64.StdEncoding.DecodeString(parsed["data"])
	if err != nil {
		return nil, err
	}

	hs, err := readClientHandshake(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}

	return processHandshake(conn, clients, hs)
}

// processHandshake validates freshness, prevents replay,
// authenticates the client, derives the session key,
// and returns an initialized session.
func processHandshake(conn net.Conn, clients []*protocol.MemoryUser, clientHS ClientHandshake) (*session.Session, error) {

	now := time.Now().Unix()
	if clientHS.Timestamp < now-60 || clientHS.Timestamp > now+60 {
		writeHTTPError(conn, 400, "timestamp invalid")
		return nil, errors.New("timestamp invalid")
	}

	if err := checkReplay(clientHS.Nonce); err != nil {
		writeHTTPError(conn, 400, "replay detected")
		return nil, err
	}

	user, err := authenticateUserBytes(clientHS.UserID, clients)
	if err != nil {
		writeHTTPError(conn, 403, "authentication failed")
		return nil, err
	}

	psk := derivePreSharedKey(clientHS.UserID)
	if len(decryptPolicy(clientHS.PolicyReq, psk)) == 0 {
		writeHTTPError(conn, 400, "invalid policy")
		return nil, errors.New("invalid policy")
	}

	serverPriv, serverPub := generateKeyPair()
	shared := deriveSharedKey(serverPriv, clientHS.PublicKey)
	sessionKey := deriveSessionKey(shared)

	serverHS := ServerHello{
		PublicKey:   serverPub,
		PolicyGrant: []byte("granted"),
	}

	respJSON, _ := json.Marshal(serverHS)

	conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"))
	conn.Write(respJSON)

	return &session.Session{
		SessionKey: sessionKey,
		WriteNonce: 0,
		ReadNonce:  0,
		User:       user,
	}, nil
}
