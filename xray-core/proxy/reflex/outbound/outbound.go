// Package outbound implements the Reflex outbound handler.
package outbound

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"io"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/retry"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func init() {
	common.Must(common.RegisterConfig((*reflex.OutboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*reflex.OutboundConfig))
	}))
}

// Handler is an outbound connection handler for the Reflex protocol.
type Handler struct {
	serverAddress net.Address
	serverPort    net.Port
	clientID      string
	policyName    string
	policyManager policy.Manager
	tlsConfig     *tls.Config
}

// New creates a new Reflex outbound handler.
func New(ctx context.Context, config *reflex.OutboundConfig) (*Handler, error) {
	v := core.MustFromContext(ctx)
	handler := &Handler{
		serverAddress: net.ParseAddress(config.GetAddress()),
		serverPort:    net.Port(config.GetPort()),
		clientID:      config.GetId(),
		policyName:    config.GetPolicy(),
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
	}

	if ech := config.GetEch(); ech != nil && ech.GetEnabled() {
		tlsCfg, err := reflex.BuildClientTLSConfig(ech)
		if err != nil {
			return nil, errors.New("failed to build client TLS+ECH config").Base(err).AtError()
		}
		handler.tlsConfig = tlsCfg
	}

	return handler, nil
}

// Process implements proxy.Outbound.Process().
func (h *Handler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return errors.New("target not specified").AtError()
	}
	ob.Name = "reflex"
	ob.CanSpliceCopy = 3
	destination := ob.Target

	serverDest := net.TCPDestination(h.serverAddress, h.serverPort)

	var conn stat.Connection
	err := retry.ExponentialBackoff(5, 200).On(func() error {
		rawConn, err := dialer.Dial(ctx, serverDest)
		if err != nil {
			return err
		}
		conn = rawConn
		return nil
	})
	if err != nil {
		return errors.New("failed to connect to reflex server").Base(err).AtWarning()
	}
	defer func() { _ = conn.Close() }()

	// If TLS+ECH is configured, wrap the outgoing TCP connection in a TLS client
	// before proceeding with the Reflex handshake.
	if h.tlsConfig != nil {
		serverName := h.tlsConfig.ServerName
		if serverName == "" {
			serverName = h.serverAddress.String()
		}
		clientTLS := h.tlsConfig.Clone()
		clientTLS.ServerName = serverName

		tlsConn := tls.Client(conn, clientTLS)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return errors.New("TLS+ECH client handshake failed").Base(err).AtWarning()
		}
		conn = stat.Connection(tlsConn)
	}

	errors.LogInfo(ctx, "tunneling request to ", destination, " via ", serverDest.NetAddr())

	// --- Perform Reflex handshake ---
	clientPrivKey, clientPubKey, err := reflex.GenerateKeyPair()
	if err != nil {
		return errors.New("failed to generate client keypair").Base(err).AtError()
	}

	userUUID, err := uuid.ParseString(h.clientID)
	if err != nil {
		return errors.New("invalid client UUID").Base(err).AtError()
	}

	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return errors.New("failed to generate nonce").Base(err).AtError()
	}

	clientHS := &reflex.ClientHandshake{
		PublicKey: clientPubKey,
		UserID:    userUUID,
		Timestamp: time.Now().Unix(),
		Nonce:     nonce,
	}

	if _, err := conn.Write(reflex.MarshalClientHandshake(clientHS)); err != nil {
		return errors.New("failed to send client handshake").Base(err).AtWarning()
	}

	// Read server handshake response
	serverHSData := make([]byte, 64)
	if _, err := io.ReadFull(conn, serverHSData); err != nil {
		return errors.New("failed to read server handshake").Base(err).AtWarning()
	}

	serverHS, err := reflex.UnmarshalServerHandshake(serverHSData)
	if err != nil {
		return errors.New("invalid server handshake").Base(err).AtWarning()
	}

	// Derive session key
	sharedSecret, err := reflex.DeriveSharedSecret(clientPrivKey, serverHS.PublicKey)
	if err != nil {
		return errors.New("key exchange failed").Base(err).AtError()
	}
	sessionKey, err := reflex.DeriveSessionKey(sharedSecret, nonce[:])
	if err != nil {
		return errors.New("session key derivation failed").Base(err).AtError()
	}

	sess, err := reflex.NewSession(sessionKey)
	if err != nil {
		return errors.New("failed to create session").Base(err).AtError()
	}

	morph := reflex.NewTrafficMorph(h.policyName)

	// --- Encrypted tunneling ---
	var newCtx context.Context
	var newCancel context.CancelFunc
	if session.TimeoutOnlyFromContext(ctx) {
		newCtx, newCancel = context.WithCancel(context.Background())
	}

	sessionPolicy := h.policyManager.ForLevel(0)
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, func() {
		cancel()
		if newCancel != nil {
			newCancel()
		}
	}, sessionPolicy.Timeouts.ConnectionIdle)

	postRequest := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)

		destData := marshalDestination(destination)

		var firstPayloadBytes []byte
		if timeoutReader, ok := link.Reader.(buf.TimeoutReader); ok {
			mb, err := timeoutReader.ReadMultiBufferTimeout(time.Millisecond * 500)
			if err == nil {
				for _, b := range mb {
					firstPayloadBytes = append(firstPayloadBytes, b.Bytes()...)
					b.Release()
				}
			} else if err != buf.ErrReadTimeout {
				return err
			}
		}

		firstFrame := append(destData, firstPayloadBytes...)
		if err := sess.WriteFrame(conn, reflex.FrameTypeData, firstFrame); err != nil {
			return errors.New("failed to write first data frame").Base(err).AtWarning()
		}

		for {
			mb, err := link.Reader.ReadMultiBuffer()
			if err != nil {
				return err
			}
			for _, b := range mb {
				data := b.Bytes()
				if morph != nil && morph.Enabled {
					if err := morph.MorphWrite(sess, conn, data); err != nil {
						b.Release()
						return errors.New("failed to write morphed frame").Base(err).AtInfo()
					}
				} else {
					if err := sess.WriteFrame(conn, reflex.FrameTypeData, data); err != nil {
						b.Release()
						return errors.New("failed to write data frame").Base(err).AtInfo()
					}
				}
				b.Release()
			}
			timer.Update()
		}
	}

	getResponse := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)

		for {
			frame, err := sess.ReadFrame(conn)
			if err != nil {
				return err
			}
			switch frame.Type {
			case reflex.FrameTypeData:
				mb := buf.MultiBuffer{buf.FromBytes(frame.Payload)}
				if err := link.Writer.WriteMultiBuffer(mb); err != nil {
					return errors.New("failed to forward response").Base(err).AtInfo()
				}
				timer.Update()
			case reflex.FrameTypePadding, reflex.FrameTypeTiming:
				if morph != nil && morph.Profile != nil {
					reflex.HandleControlFrame(frame, morph.Profile)
				}
				continue
			case reflex.FrameTypeClose:
				return nil
			default:
				return errors.New("unknown frame type from server")
			}
		}
	}

	if newCtx != nil {
		ctx = newCtx
	}

	responseDoneAndCloseWriter := task.OnSuccess(getResponse, task.Close(link.Writer))
	if err := task.Run(ctx, postRequest, responseDoneAndCloseWriter); err != nil {
		return errors.New("connection ends").Base(err).AtInfo()
	}

	return nil
}

// marshalDestination encodes a destination as [addrType(1)] [addr] [port(2)].
func marshalDestination(dest net.Destination) []byte {
	var data []byte
	addr := dest.Address

	switch {
	case addr.Family().IsIP():
		ip := addr.IP()
		if len(ip) == 4 {
			data = append(data, 1) // IPv4
			data = append(data, ip...)
		} else {
			data = append(data, 3) // IPv6
			data = append(data, ip...)
		}
	case addr.Family().IsDomain():
		domain := addr.Domain()
		data = append(data, 2) // Domain
		data = append(data, byte(len(domain)))
		data = append(data, []byte(domain)...)
	}

	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(dest.Port))
	data = append(data, portBytes...)

	return data
}
