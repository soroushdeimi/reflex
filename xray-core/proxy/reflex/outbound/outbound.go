package outbound

import (
	"context"
	"encoding/binary"
	"io"
	"strings"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/retry"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/proxy/reflex/encoding"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*Config))
	}))
	common.Must(common.RegisterConfig((*reflex.OutboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		cfg := config.(*reflex.OutboundConfig)
		return New(ctx, &Config{
			Address: cfg.Address,
			Port:    cfg.Port,
			UserID:  cfg.Id,
		})
	}))
}

// Handler is the outbound connection handler for Reflex protocol
type Handler struct {
	address string
	port    uint32
	userID  string
	policy  string
}

// New creates a new Reflex outbound handler
func New(ctx context.Context, config *Config) (*Handler, error) {
	handler := &Handler{
		address: config.Address,
		port:    config.Port,
		userID:  config.UserID,
		policy:  config.Policy,
	}

	return handler, nil
}

// Process processes an outbound connection
func (h *Handler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	var rawConn stat.Connection
	err := retry.ExponentialBackoff(5, 100).On(func() error {
		dest := net.TCPDestination(net.ParseAddress(h.address), net.Port(h.port))
		var err error
		rawConn, err = dialer.Dial(ctx, dest)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return errors.New("failed to dial Reflex server").Base(err)
	}
	defer func() {
		_ = rawConn.Close()
	}()

	// Generate client key pair
	clientKeyPair, err := encoding.GenerateKeyPair()
	if err != nil {
		return err
	}

	// Parse User ID
	parsedID, err := uuid.Parse(h.userID)
	if err != nil {
		return errors.New("invalid user ID").Base(err)
	}

	// Send client handshake
	clientHS := encoding.NewClientHandshake(parsedID, clientKeyPair.PublicKey)
	clientHSBytes := encoding.MarshalClientHandshake(clientHS)
	packet := make([]byte, 4+len(clientHSBytes))
	binary.BigEndian.PutUint32(packet[:4], reflex.ReflexMagic)
	copy(packet[4:], clientHSBytes)

	if _, err := rawConn.Write(packet); err != nil {
		return errors.New("failed to send client handshake").Base(err)
	}

	// Receive server handshake
	headerBuf := make([]byte, 1024)
	n, err := rawConn.Read(headerBuf)
	if err != nil {
		return errors.New("failed to read server response").Base(err)
	}

	headerStr := string(headerBuf[:n])
	dataIndex := strings.Index(headerStr, "\r\n\r\n")
	if dataIndex == -1 {
		return errors.New("invalid server response header")
	}
	dataIndex += 4

	serverHSBytes := headerBuf[dataIndex:n]
	if len(serverHSBytes) < 32 {
		remaining := 32 - len(serverHSBytes)
		extra := make([]byte, remaining)
		if _, err := io.ReadFull(rawConn, extra); err != nil {
			return err
		}
		serverHSBytes = append(serverHSBytes, extra...)
	}

	serverHS, err := encoding.UnmarshalServerHandshake(serverHSBytes[:32])
	if err != nil {
		return err
	}

	// Derive shared secret and session key
	sharedSecret, err := encoding.DeriveSharedSecret(clientKeyPair.PrivateKey, serverHS.PublicKey)
	if err != nil {
		return err
	}

	sessionKey, err := encoding.DeriveSessionKey(sharedSecret, []byte("reflex-session"), []byte("reflex"))
	if err != nil {
		return err
	}

	// Create session
	sess, err := encoding.NewSession(sessionKey)
	if err != nil {
		return err
	}

	// Get traffic profile
	var profile *encoding.TrafficProfile
	if h.policy != "" {
		profile = encoding.Profiles[h.policy]
	}

	// Get target destination
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 {
		return errors.New("target destination not found")
	}
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return errors.New("target destination not found")
	}
	dest := ob.Target

	// Encode and send destination in first data frame
	addrData := encodeAddress(dest)
	if err := sess.WriteFrameWithMorphing(rawConn, reflex.FrameTypeData, addrData, profile); err != nil {
		return err
	}

	// Bidirectional copy
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	requestDone := func() error {
		for {
			mb, err := link.Reader.ReadMultiBuffer()
			if err != nil {
				return err
			}
			for _, b := range mb {
				if err := sess.WriteFrameWithMorphing(rawConn, reflex.FrameTypeData, b.Bytes(), profile); err != nil {
					b.Release()
					return err
				}
				b.Release()
			}
		}
	}

	responseDone := func() error {
		for {
			frame, err := sess.ReadFrame(rawConn)
			if err != nil {
				return err
			}
			switch frame.Type {
			case reflex.FrameTypeData:
				if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(frame.Payload)}); err != nil {
					return err
				}
			case reflex.FrameTypeClose:
				return nil
			}
		}
	}

	return task.Run(ctx, requestDone, responseDone)
}

func encodeAddress(dest net.Destination) []byte {
	var data []byte
	switch dest.Address.Family() {
	case net.AddressFamilyIPv4:
		data = append(data, 1)
		data = append(data, byte(dest.Port>>8), byte(dest.Port))
		data = append(data, dest.Address.IP()...)
	case net.AddressFamilyDomain:
		data = append(data, 2)
		data = append(data, byte(dest.Port>>8), byte(dest.Port))
		domain := dest.Address.Domain()
		data = append(data, byte(len(domain)))
		data = append(data, []byte(domain)...)
	case net.AddressFamilyIPv6:
		data = append(data, 3)
		data = append(data, byte(dest.Port>>8), byte(dest.Port))
		data = append(data, dest.Address.IP()...)
	}
	return data
}
