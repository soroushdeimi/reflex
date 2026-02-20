package outbound

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"time"

	"github.com/xtls/xray-core/common"
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
	privKey, pubKey, err := reflex.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	parsedUUID, err := uuid.ParseString(h.clientId)
	if err != nil {
		return nil, err
	}

	// ۱. ارسال مجیک و تمام دیتای هندشیک در یک مرحله
	fullPayload := make([]byte, 4+64) // 4 (Magic) + 64 (Handshake)

	// Magic
	binary.BigEndian.PutUint32(fullPayload[:4], reflex.ReflexMagic)

	// Handshake Data (32 + 16 + 8 + 8)
	copy(fullPayload[4:36], pubKey[:])
	uid := [16]byte(parsedUUID)
	copy(fullPayload[36:52], uid[:])
	binary.BigEndian.PutUint64(fullPayload[52:60], uint64(time.Now().Unix()))
	if _, err := rand.Read(fullPayload[60:68]); err != nil {
		return nil, err
	}

	// نوشتن کل بسته به صورت یک‌جا
	if _, err := conn.Write(fullPayload); err != nil {
		return nil, err
	}

	// ۲. دریافت پاسخ سرور (۳۲ بایت کلید عمومی)
	respPubKey := make([]byte, 32)
	if _, err := io.ReadFull(conn, respPubKey); err != nil {
		return nil, err
	}

	var sPubKey [32]byte
	copy(sPubKey[:], respPubKey)

	// ۳. استخراج کلید
	shared := reflex.DeriveSharedKey(privKey, sPubKey)
	// استفاده از نانس ارسالی در سالت (بایت ۶۰ تا ۶۸)
	salt := append(fullPayload[60:68], uid[:]...)
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
