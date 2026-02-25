package tunnel

// Step3 wire framing for Reflex.
//
// Wire format:
//   [Length:2B big-endian][Type:1B][Ciphertext...]
//
// Length is the number of bytes of Ciphertext that follows (NOT plaintext length).

const (
	FrameTypeData    = 0x01
	FrameTypePadding = 0x02
	FrameTypeTiming  = 0x03
	FrameTypeClose   = 0x04
)

const (
	// FrameHeaderLen is the number of bytes in the unencrypted header.
	FrameHeaderLen = 3
)

// Frame is a logical decoded frame.
//
// Length is the ciphertext length on the wire.
// Payload is the DECRYPTED plaintext.
type Frame struct {
	Length  uint16
	Type    uint8
	Payload []byte
}
