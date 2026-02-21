package inbound

const ReflexMagic uint32 = 0x5246584C // "REFXL"

type ClientHandshake struct {
	PublicKey [32]byte
	UserID    [16]byte
	PolicyReq []byte
	Timestamp int64
	Nonce     [16]byte
}

// اضافه
func (c ClientHandshake) UnmarshalBinary(rawHandshake []byte) any {
	panic("unimplemented")
}

type ClientHandshakePacket struct {
	Magic     [4]byte
	Handshake ClientHandshake
}

type ServerHandshake struct {
	PublicKey   [32]byte
	PolicyGrant []byte
}
