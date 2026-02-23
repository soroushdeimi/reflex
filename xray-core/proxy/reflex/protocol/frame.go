package protocol

// Frame types used in Reflex encrypted session.
const (
	FrameTypeData    = 0x01
	FrameTypePadding = 0x02
	FrameTypeTiming  = 0x03
	FrameTypeClose   = 0x04
)

// Address types used inside first DATA frame payload.
const (
	AddrTypeIPv4   = 0x01
	AddrTypeDomain = 0x02
	AddrTypeIPv6   = 0x03
)
