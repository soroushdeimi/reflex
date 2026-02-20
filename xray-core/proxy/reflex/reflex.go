package reflex

//go:generate go run github.com/xtls/xray-core/common/errors/errorgen

const (
	// ReflexMagic is the magic number for quick protocol detection
	ReflexMagic uint32 = 0x5246584C // "REFX" in ASCII
)

// Frame types
const (
	FrameTypeData    = 0x01 // DATA frame - actual user data
	FrameTypePadding = 0x02 // PADDING_CTRL frame - padding control
	FrameTypeTiming  = 0x03 // TIMING_CTRL frame - timing control
	FrameTypeClose   = 0x04 // CLOSE frame - close connection
)

// Frame represents a Reflex protocol frame
type Frame struct {
	Length  uint16 // Length of encrypted payload
	Type    uint8  // Frame type
	Payload []byte // Encrypted payload
}
