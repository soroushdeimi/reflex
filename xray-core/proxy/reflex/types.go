package reflex

const ReflexMagic uint32 = 0x5246584C

type ClientHandshake struct {
	PublicKey [32]byte
	UserID    [16]byte
	Timestamp int64
	Nonce     [8]byte
}

type ClientHandshakePacket struct {
	Magic     [4]byte
	Handshake ClientHandshake
}

type ServerHandshake struct {
	PublicKey   [32]byte
	PolicyGrant []byte
}

const (
	FrameTypeData    uint8 = 0x01
	FrameTypePadding uint8 = 0x02
	FrameTypeTiming  uint8 = 0x03
	FrameTypeClose   uint8 = 0x04
)
