package outbound

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/retry"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

type Handler struct {
	serverAddress net.Destination
	clientId      string
}

func (h *Handler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	var conn net.Conn // Changed to net.Conn for better compatibility
	err := retry.ExponentialBackoff(5, 100).On(func() error {
		rawConn, err := dialer.Dial(ctx, h.serverAddress)
		if err != nil {
			return err
		}
		conn = rawConn
		return nil
	})
	if err != nil {
		return err
	}
	defer conn.Close()

	// Step 2: Handshake
	sessionKey, err := h.clientHandshake(conn)
	if err != nil {
		return err
	}

	_ = sessionKey
	_ = link
	return nil
}

func (h *Handler) clientHandshake(conn net.Conn) ([]byte, error) {
	// 1. Key generation
	privKey, pubKey, err := reflex.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	parsedUUID, err := uuid.ParseString(h.clientId)
	if err != nil {
		return nil, err
	}

	hs := &reflex.ClientHandshake{
		PublicKey: pubKey,
		UserID:    [16]byte(parsedUUID),
		Timestamp: time.Now().Unix(),
	}
	if _, err := rand.Read(hs.Nonce[:]); err != nil {
		return nil, err
	}

	// 2. Send Reflex Magic
	magic := make([]byte, 4)
	binary.BigEndian.PutUint32(magic, reflex.ReflexMagic)
	if _, err := conn.Write(magic); err != nil {
		return nil, err
	}

	// 3. Send Handshake Payload
	hsBuf := buf.New()
	defer hsBuf.Release()

	// Handle two return values from Write
	_, _ = hsBuf.Write(hs.PublicKey[:])
	_, _ = hsBuf.Write(hs.UserID[:])

	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(hs.Timestamp))
	_, _ = hsBuf.Write(ts)
	_, _ = hsBuf.Write(hs.Nonce[:])

	if _, err := conn.Write(hsBuf.Bytes()); err != nil {
		return nil, err
	}

	// 4. Receive Server Public Key
	sPubKeyRaw := make([]byte, 32)
	if _, err := conn.Read(sPubKeyRaw); err != nil {
		return nil, err
	}

	var sPubKey [32]byte
	copy(sPubKey[:], sPubKeyRaw)

	// 5. Derive Session Key
	shared := reflex.DeriveSharedKey(privKey, sPubKey)
	salt := append(hs.Nonce[:], hs.UserID[:]...)
	return reflex.DeriveSessionKey(shared, salt)
}

func New(ctx context.Context, config *reflex.OutboundConfig) (proxy.Outbound, error) {
	return &Handler{
		serverAddress: net.Destination{
			Network: net.Network_TCP,
			Address: net.ParseAddress(config.Address),
			Port:    net.Port(config.Port),
		},
		clientId: config.Id,
	}, nil
}

func init() {
	common.Must(common.RegisterConfig(
		(*reflex.OutboundConfig)(nil),
		func(ctx context.Context, config interface{}) (interface{}, error) {
			return New(ctx, config.(*reflex.OutboundConfig))
		},
	))
}
