package reflex

// Protocol name for Reflex
const (
	ProtocolName = "reflex"
)

// Frame type constants
const (
	FrameTypeData    = 0x01
	FrameTypePadding = 0x02
	FrameTypeTiming  = 0x03
	FrameTypeClose   = 0x04
)

// Magic number for Reflex protocol detection ("REFX")
const ReflexMagic uint32 = 0x5246584C

// Default values
const (
	DefaultHandshakeSize = 256
	NonceSizeChaCha20    = 12
	KeySizeChaCha20      = 32
)
