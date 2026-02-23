package inbound

import (
	"encoding/binary"
	"errors"
)

const ReflexMagic uint32 = 0x5246584C // "REFXL"

type ClientHandshake struct {
	PublicKey [32]byte
	UserID    [16]byte
	PolicyReq []byte
	Timestamp int64
	Nonce     [16]byte
}

type ClientHandshakePacket struct {
	Magic     [4]byte
	Handshake ClientHandshake
}

type ServerHandshake struct {
	PublicKey   [32]byte
	PolicyGrant []byte
}

// Parse the binary handshake into structured fields.
func (c *ClientHandshake) UnmarshalBinary(b []byte) error {
	//The length does not contain PolicyReq, the remaining bytes are PolicyReq.
	const cfgLen = 32 + 16 + 8 + 16

	if len(b) < cfgLen {
		return errors.New("handshake packet too short")
	}

	offset := 0

	// PublicKey
	copy(c.PublicKey[:], b[offset:offset+32])
	offset += 32

	// UserID
	copy(c.UserID[:], b[offset:offset+16])
	offset += 16

	// Timestamp
	c.Timestamp = int64(binary.BigEndian.Uint64(b[offset : offset+8]))
	offset += 8

	// Nonce
	copy(c.Nonce[:], b[offset:offset+16])
	offset += 16

	// Policy
	if offset < len(b) {
		c.PolicyReq = make([]byte, len(b)-offset)
		copy(c.PolicyReq, b[offset:])
	} else {
		c.PolicyReq = nil
	}

	return nil
}
