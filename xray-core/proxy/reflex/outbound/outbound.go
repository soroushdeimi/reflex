package outbound

import (
	"context"
	"encoding/binary"
	"io"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/retry"

	// "github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type Handler struct {
	config *reflex.OutboundConfig
}

// New creates a new Reflex outbound handler.
func New(ctx context.Context, config *reflex.OutboundConfig) (*Handler, error) {
	return &Handler{
		config: config,
	}, nil
}

// Process implements OutboundHandler.Process().
func (h *Handler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	var conn stat.Connection
	err := retry.ExponentialBackoff(5, 100).On(func() error {
		dest := net.TCPDestination(net.ParseAddress(h.config.Address), net.Port(h.config.Port))
		c, err := dialer.Dial(ctx, dest)
		if err != nil {
			return err
		}
		conn = c
		return nil
	})
	if err != nil {
		return err
	}
	defer conn.Close()

	// 1. Generate handshake
	priv, pub, err := reflex.GenerateKeyPair()
	if err != nil {
		return err
	}

	uID, err := uuid.ParseString(h.config.Id)
	if err != nil {
		return err
	}

	var uIDBytes [16]byte
	copy(uIDBytes[:], uID.Bytes())

	handshake := reflex.ClientHandshake{
		PublicKey: pub,
		UserID:    uIDBytes,
		Timestamp: time.Now().Unix(),
		Nonce:     [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
	}

	// 2. Send Magic + Handshake
	if err := binary.Write(conn, binary.BigEndian, reflex.ReflexMagic); err != nil {
		return err
	}
	if _, err := conn.Write(handshake.Serialize()); err != nil {
		return err
	}

	// 3. Setup Session
	var serverPubKey [32]byte
	if _, err := io.ReadFull(conn, serverPubKey[:]); err != nil {
		return err
	}
	var serverNonce [16]byte
	if _, err := io.ReadFull(conn, serverNonce[:]); err != nil {
		return err
	}

	sessionKey, err := reflex.DeriveSessionKeys(priv, serverPubKey)
	if err != nil {
		return err
	}

	s, err := reflex.NewSession(sessionKey)
	if err != nil {
		return err
	}

	requestFunc := func() error {
		for {
			payload, err := link.Reader.ReadMultiBuffer()
			if err != nil {
				if err == io.EOF {
					return nil
				}
				return err
			}
			for _, b := range payload {
				if err := s.WriteFrame(conn, reflex.FrameTypeData, b.Bytes()); err != nil {
					return err
				}
				b.Release()
			}
		}
	}

	responseFunc := func() error {
		for {
			frame, err := s.ReadFrame(conn)
			if err != nil {
				if err == io.EOF {
					return nil
				}
				return err
			}
			if frame.Type == reflex.FrameTypeData {
				b := buf.New()
				b.Write(frame.Payload)
				if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
					return err
				}
			}
		}
	}

	if err := task.Run(ctx, requestFunc, responseFunc); err != nil {
		return err
	}

	return nil
}

func init() {
	common.Must(common.RegisterConfig((*reflex.OutboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*reflex.OutboundConfig))
	}))
}
