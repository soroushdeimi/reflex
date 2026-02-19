package outbound

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

type Handler struct {
	policyManager policy.Manager
	config        *reflex.OutboundConfig
}

func New(ctx context.Context, config *reflex.OutboundConfig) (*Handler, error) {
	v := core.MustFromContext(ctx)
	return &Handler{
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
		config:        config,
	}, nil
}

func (h *Handler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	if h.config.Address == "" || h.config.Port == 0 {
		return newError("server address not configured")
	}

	destination := xnet.Destination{
		Network: xnet.Network_TCP,
		Address: xnet.ParseAddress(h.config.Address),
		Port:    xnet.Port(h.config.Port),
	}

	conn, err := dialer.Dial(ctx, destination)
	if err != nil {
		return newError("failed to dial server: ", destination).Base(err)
	}
	defer conn.Close()

	sessionPolicy := h.policyManager.ForLevel(0)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	timer := signal.CancelAfterInactivity(ctx, cancel, sessionPolicy.Timeouts.ConnectionIdle)

	// Handshake
	sessionKeys, err := h.performHandshake(ctx, conn)
	if err != nil {
		return newError("handshake failed").Base(err)
	}

	// Create session ONCE
	sess, err := reflex.NewClientSession(sessionKeys)
	if err != nil {
		return newError("failed to create session").Base(err)
	}

	requestDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)
		return h.handleUplink(ctx, link.Reader, conn, sess)
	}

	responseDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)
		return h.handleDownlink(ctx, link.Writer, conn, sess)
	}

	if err := task.Run(ctx, requestDone, responseDone); err != nil {
		return newError("connection ends").Base(err)
	}

	return nil
}

func (h *Handler) performHandshake(ctx context.Context, conn net.Conn) (*reflex.SessionKeys, error) {
	clientPriv, clientPub, err := reflex.GenerateKeyPair()
	if err != nil {
		return nil, newError("failed to generate keypair").Base(err)
	}

	clientNonce, err := reflex.GenerateNonce()
	if err != nil {
		return nil, newError("failed to generate nonce").Base(err)
	}

	var userID [16]byte
	if h.config.Id != "" {
		uidBytes, err := reflex.UUIDToBytes(h.config.Id)
		if err != nil {
			return nil, newError("invalid user ID").Base(err)
		}
		userID = uidBytes
	}

	clientHS := &reflex.ClientHandshake{
		PublicKey: clientPub,
		UserID:    userID,
		Timestamp: time.Now().Unix(),
		Nonce:     clientNonce,
		PolicyReq: []byte{},
	}

	hsData := reflex.MarshalClientHandshake(clientHS)

	request := make([]byte, 4+2+len(hsData))
	binary.BigEndian.PutUint32(request[0:4], reflex.ReflexMagic)
	binary.BigEndian.PutUint16(request[4:6], uint16(len(hsData)))
	copy(request[6:], hsData)

	if err := conn.SetDeadline(time.Now().Add(reflex.HandshakeTimeout)); err != nil {
		return nil, newError("failed to set deadline").Base(err)
	}

	if _, err := conn.Write(request); err != nil {
		return nil, newError("failed to send handshake").Base(err)
	}

	respHeader := make([]byte, 6)
	if _, err := io.ReadFull(conn, respHeader); err != nil {
		return nil, newError("failed to read response header").Base(err)
	}

	if binary.BigEndian.Uint32(respHeader[0:4]) != reflex.ReflexMagic {
		return nil, newError("invalid response magic")
	}

	respLen := binary.BigEndian.Uint16(respHeader[4:6])
	if respLen > 4096 {
		return nil, newError("response too large")
	}

	respData := make([]byte, respLen)
	if _, err := io.ReadFull(conn, respData); err != nil {
		return nil, newError("failed to read response data").Base(err)
	}

	serverHS, err := reflex.UnmarshalServerHandshake(respData)
	if err != nil {
		return nil, newError("failed to unmarshal server handshake").Base(err)
	}

	if !reflex.ValidateTimestamp(serverHS.Timestamp) {
		return nil, newError("invalid server timestamp")
	}

	sharedKey, err := reflex.DeriveSharedKey(clientPriv, serverHS.PublicKey)
	if err != nil {
		return nil, newError("failed to derive shared key").Base(err)
	}

	var serverNonce [16]byte
	binary.BigEndian.PutUint64(serverNonce[0:8], uint64(serverHS.Timestamp))
	binary.BigEndian.PutUint64(serverNonce[8:16], uint64(serverHS.Timestamp))

	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, newError("failed to clear deadline").Base(err)
	}

	return reflex.DeriveSessionKeys(sharedKey, clientNonce, serverNonce)
}

// handleUplink sends data to server (encrypted)
func (h *Handler) handleUplink(
	ctx context.Context,
	reader buf.Reader,
	conn net.Conn,
	sess *reflex.Session,
) error {
	for {
		mb, err := reader.ReadMultiBuffer()
		if err != nil {
			sess.WriteFrame(conn, reflex.FrameTypeClose, nil, false)
			return nil
		}

		for _, b := range mb {
			if err := sess.WriteFrame(conn, reflex.FrameTypeData, b.Bytes(), false); err != nil {
				b.Release()
				return newError("failed to write frame").Base(err)
			}
			b.Release()
		}
	}
}

// handleDownlink receives data from server (decrypted)
func (h *Handler) handleDownlink(
	ctx context.Context,
	writer buf.Writer,
	conn net.Conn,
	sess *reflex.Session,
) error {
	bufReader := bufio.NewReader(conn)

	for {
		frame, err := sess.ReadFrame(bufReader, false)
		if err != nil {
			return err
		}

		switch frame.Type {
		case reflex.FrameTypeData:
			b := buf.FromBytes(frame.Payload)
			if err := writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
				return newError("failed to write data").Base(err)
			}

		case reflex.FrameTypeClose:
			return nil

		case reflex.FrameTypePadding, reflex.FrameTypeTiming:
			continue

		default:
			return newError("unknown frame type: ", frame.Type)
		}
	}
}

func newError(values ...interface{}) *errors.Error {
	return errors.New(values...).AtWarning()
}

func init() {
	common.Must(common.RegisterConfig((*reflex.OutboundConfig)(nil),
		func(ctx context.Context, config interface{}) (interface{}, error) {
			return New(ctx, config.(*reflex.OutboundConfig))
		}))
}
