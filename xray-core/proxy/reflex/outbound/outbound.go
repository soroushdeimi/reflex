package outbound

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"time"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	sess "github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

// Handler implements the outbound side of the Reflex protocol.
// هندلر سمت خروجی (اوتباند) پروتکل رفلکس.
type Handler struct {
	config *reflex.OutboundConfig
}

// Process initiates a connection to the Reflex server and handles data forwarding.
// اتصال به سرور رفلکس را برقرار کرده و فوروارد داده‌ها را مدیریت می‌کند.
func (h *Handler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	conn, err := dialer.Dial(ctx, net.TCPDestination(net.ParseAddress(h.config.Address), net.Port(h.config.Port)))
	if err != nil {
		return err
	}

	if h.config.Tls != nil && h.config.Tls.Enabled {
		serverName := h.config.Tls.ServerName
		if serverName == "" {
			serverName = h.config.Address
		}
		tlsConfig := &tls.Config{
			ServerName: serverName,
		}

		if len(h.config.Tls.EchKey) > 0 {
			echKey := h.config.Tls.EchKey
			// Auto-wrap if it's a single ECHConfig (starts with version 0xfe0d)
			// and doesn't already have the ECHConfigList length prefix.
			if len(echKey) >= 4 && echKey[0] == 0xfe && echKey[1] == 0x0d {
				wrapped := make([]byte, 2+len(echKey))
				binary.BigEndian.PutUint16(wrapped[0:2], uint16(len(echKey)))
				copy(wrapped[2:], echKey)
				echKey = wrapped
			}
			tlsConfig.EncryptedClientHelloConfigList = echKey
		}

		tlsConn := tls.Client(conn, tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			tlsConn.Close()
			return err
		}
		conn = tlsConn
	}

	defer conn.Close()

	// Client Handshake
	clientPriv, clientPub, err := reflex.GenerateKeyPair()
	if err != nil {
		return err
	}

	u, err := uuid.Parse(h.config.Id)
	if err != nil {
		return err
	}
	var userId [16]byte
	copy(userId[:], u[:])

	var nonce [16]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return err
	}

	clientHS := reflex.ClientHandshake{
		PublicKey: clientPub,
		UserID:    userId,
		Timestamp: time.Now().Unix(),
		Nonce:     nonce,
	}

	// Send Magic
	magic := make([]byte, 4)
	binary.BigEndian.PutUint32(magic, reflex.ReflexMagic)
	if _, err := conn.Write(magic); err != nil {
		return err
	}

	// Send Handshake
	if err := binary.Write(conn, binary.BigEndian, &clientHS); err != nil {
		return err
	}

	// Read Server Handshake
	var serverHS reflex.ServerHandshake
	if err := binary.Read(conn, binary.BigEndian, &serverHS); err != nil {
		return err
	}

	sharedKey := reflex.DeriveSharedKey(clientPriv, serverHS.PublicKey)
	c2s, s2c := reflex.DeriveSessionKeys(sharedKey, []byte("reflex-session"))

	session, err := reflex.NewSession(s2c, c2s) // Read is S2C, Write is C2S
	if err != nil {
		return err
	}

	// Send destination in first DATA frame
	outbounds := sess.OutboundsFromContext(ctx)
	if len(outbounds) == 0 {
		return errors.New("no outbound destination found")
	}
	target := outbounds[0].Target
	if !target.IsValid() {
		return errors.New("invalid target")
	}

	addrParser := protocol.NewAddressParser(
		protocol.AddressFamilyByte(0x01, net.AddressFamilyIPv4),
		protocol.AddressFamilyByte(0x02, net.AddressFamilyDomain),
		protocol.AddressFamilyByte(0x03, net.AddressFamilyIPv6),
	)

	addrBuf := buf.New()
	defer addrBuf.Release()

	// Write Network byte
	networkByte := reflex.NetworkTCP
	if target.Network == net.Network_UDP {
		networkByte = reflex.NetworkUDP
	}
	addrBuf.WriteByte(byte(networkByte))

	if err := addrParser.WriteAddressPort(addrBuf, target.Address, target.Port); err != nil {
		return err
	}

	if err := session.WriteFrame(conn, reflex.FrameTypeData, addrBuf.Bytes()); err != nil {
		return err
	}

	// Bidirectional forwarding
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		defer cancel()
		for {
			mb, err := link.Reader.ReadMultiBuffer()
			if err != nil {
				break
			}
			for _, b := range mb {
				if err := session.WriteFrame(conn, reflex.FrameTypeData, b.Bytes()); err != nil {
					b.Release()
					return
				}
				b.Release()
			}
		}
		session.WriteFrame(conn, reflex.FrameTypeClose, nil)
	}()

	for {
		frame, err := session.ReadFrame(conn)
		if err != nil {
			break
		}
		if frame.Type == reflex.FrameTypeClose {
			break
		}
		switch frame.Type {
		case reflex.FrameTypeData:
			if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(frame.Payload)}); err != nil {
				return err
			}
		case reflex.FrameTypePadding, reflex.FrameTypeTiming:
			// In a real scenario, the client would also have a profile
			// For now, we can just handle them or ignore.
			session.HandleControlFrame(frame, nil)
		}
	}

	return nil
}

func init() {
	common.Must(common.RegisterConfig((*reflex.OutboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*reflex.OutboundConfig))
	}))
}

func New(ctx context.Context, config *reflex.OutboundConfig) (proxy.Outbound, error) {
	return &Handler{
		config: config,
	}, nil
}
