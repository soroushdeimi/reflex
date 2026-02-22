package reflex

import (
	"math/rand"
	"time"
)

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

type PacketSizeDist struct {
	Size   int
	Weight float64
}

type TrafficProfile struct {
	Name        string
	PacketSizes []PacketSizeDist
}

var AparatProfile = TrafficProfile{
	Name: "Aparat",
	PacketSizes: []PacketSizeDist{
		{Size: 1450, Weight: 0.8},
		{Size: 500, Weight: 0.1},
		{Size: 100, Weight: 0.1},
	},
}

func (p *TrafficProfile) GetRandomTargetSize() int {
	rand.Seed(time.Now().UnixNano())

	r := rand.Float64()
	var cumulative float64

	for _, dist := range p.PacketSizes {
		cumulative += dist.Weight
		if r <= cumulative {
			return dist.Size
		}
	}
	return 1450
}
