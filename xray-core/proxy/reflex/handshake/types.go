package handshake

// This package defines wire-agnostic handshake data models for Reflex.
// Codecs (magic / http-like) are responsible for encoding/decoding these types
// to/from the network stream.

const (
	// X25519 public key size.
	PublicKeySize = 32

	// UUID raw bytes size.
	UserIDSize = 16

	// Nonce size used for replay protection (per spec step2).
	NonceSize = 16

	// Suggested maximum sizes to avoid memory abuse.
	MaxPolicyReqSize   = 4 * 1024 // 4KB
	MaxPolicyGrantSize = 4 * 1024 // 4KB

	// Suggested limits for parsing an HTTP-like request.
	// (These are not used yet; codec/http.go will use them.)
	MaxHTTPHeaderBytes = 8 * 1024  // 8KB headers cap
	MaxHTTPBodyBytes   = 16 * 1024 // 16KB body cap (JSON + base64)
)

// ReflexMagicUint32 is the optional magic number for fast detection.
// Value is 0x5246584C in big-endian (bytes: 'R','F','X','L').
//
// NOTE: The spec comment says "REFX" but this constant maps to "RFXL".
// We follow the numeric value (0x5246584C) as the source of truth.
const ReflexMagicUint32 uint32 = 0x5246584C

var ReflexMagicBytes = [4]byte{0x52, 0x46, 0x58, 0x4C} // "RFXL"

// ClientHandshake is the logical handshake message sent by client.
// Wire encoding is handled by codecs.
type ClientHandshake struct {
	PublicKey [PublicKeySize]byte // ephemeral X25519 public key
	UserID    [UserIDSize]byte    // UUID raw bytes
	PolicyReq []byte              // encrypted with PSK (derived from UUID hash)
	Timestamp int64               // unix timestamp
	Nonce     [NonceSize]byte     // replay protection
}

// ServerHandshake is the logical handshake message sent by server.
type ServerHandshake struct {
	PublicKey   [PublicKeySize]byte // server ephemeral X25519 public key
	PolicyGrant []byte              // encrypted grant
}

// Canonical binary encoding proposal (for magic codec)
// ---------------------------------------------------
// Client (after 4-byte magic):
//   pubkey(32) | userid(16) | timestamp(8, big-endian) | nonce(16) | policyLen(2, big-endian) | policyReq(policyLen)
//
// Server:
//   pubkey(32) | grantLen(2, big-endian) | policyGrant(grantLen)
//
// The HTTP-like codec will base64-encode the same "binary payload" above (without magic).
