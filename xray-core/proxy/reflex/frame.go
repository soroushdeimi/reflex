package reflex

// Frame type constants
const (
	FrameTypeData    = 0x01 // User data
	FrameTypePadding = 0x02 // Padding control
	FrameTypeTiming  = 0x03 // Timing control
	FrameTypeClose   = 0x04 // Close connection
)

// Frame represents an encrypted frame
type Frame struct {
	Length  uint16
	Type    uint8
	Payload []byte
}

// FrameHeaderSize is the size of frame header (length + type)
const FrameHeaderSize = 3

// MaxFrameSize limits maximum frame payload size (64KB)
const MaxFrameSize = 65535
