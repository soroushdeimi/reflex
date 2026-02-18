package reflex

const (
	FrameTypeData    = 0x01
	FrameTypePadding = 0x02
	FrameTypeTiming  = 0x03
	FrameTypeClose   = 0x04
)

type Frame struct {
	Length  uint16
	Type    uint8
	Payload []byte
}

