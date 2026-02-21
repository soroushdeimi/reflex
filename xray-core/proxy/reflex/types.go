package reflex

const ReflexMagic uint32 = 0x5246584C

type ClientHandshake struct {
	PublicKey [32]byte
	UserID    [16]byte
	Timestamp int64
	Nonce     [8]byte // حتماً ۸ بایت باشد تا با پکت ۶۴ بایتی هماهنگ شود
}

type ClientHandshakePacket struct {
	Magic     [4]byte
	Handshake ClientHandshake
}

type ServerHandshake struct {
	PublicKey   [32]byte
	PolicyGrant []byte
}
