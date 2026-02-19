package outbound

import (
	"context"
	"encoding/binary"
	"io"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

// Handler is the outbound handler for Reflex protocol
type Handler struct {
	policyManager policy.Manager
	config        *reflex.OutboundConfig
}

// New creates a new Reflex outbound handler
func New(ctx context.Context, config *reflex.OutboundConfig) (*Handler, error) {
	v := core.MustFromContext(ctx)

	handler := &Handler{
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
		config:        config,
	}

	return handler, nil
}

// Process handles outbound connection
func (h *Handler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	// Validate config
	if h.config.Address == "" || h.config.Port == 0 {
		return newError("server address not configured")
	}

	// Get destination from config
	destination := net.Destination{
		Network: net.Network_TCP,
		Address: net.ParseAddress(h.config.Address),
		Port:    net.Port(h.config.Port),
	}

	// Dial server
	conn, err := dialer.Dial(ctx, destination)
	if err != nil {
		return newError("failed to dial server: ", destination).Base(err)
	}
	defer conn.Close()

	// Get policy
	sessionPolicy := h.policyManager.ForLevel(0)
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, cancel, sessionPolicy.Timeouts.ConnectionIdle)

	// Perform handshake
	sessionKeys, err := h.performHandshake(ctx, conn)
	if err != nil {
		return newError("handshake failed").Base(err)
	}

	// Handle session
	requestDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)
		return h.handleUplink(ctx, link.Reader, conn, sessionKeys)
	}

	responseDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)
		return h.handleDownlink(ctx, link.Writer, conn, sessionKeys)
	}

	if err := task.Run(ctx, requestDone, responseDone); err != nil {
		return newError("connection ends").Base(err)
	}

	return nil
}

// performHandshake performs client-side handshake
func (h *Handler) performHandshake(ctx context.Context, conn net.Conn) (*reflex.SessionKeys, error) {
	// Generate client key pair
	clientPriv, clientPub, err := reflex.GenerateKeyPair()
	if err != nil {
		return nil, newError("failed to generate key pair").Base(err)
	}

	// Generate nonce
	clientNonce, err := reflex.GenerateNonce()
	if err != nil {
		return nil, newError("failed to generate nonce").Base(err)
	}

	// Get user ID from config
	var userID [16]byte
	if h.config.Id != "" {
		uidBytes, err := reflex.UUIDToBytes(h.config.Id)
		if err != nil {
			return nil, newError("invalid user ID").Base(err)
		}
		userID = uidBytes
	}

	// Create client handshake
	clientHS := &reflex.ClientHandshake{
		PublicKey: clientPub,
		UserID:    userID,
		Timestamp: time.Now().Unix(),
		Nonce:     clientNonce,
		PolicyReq: []byte{},
	}

	// Marshal handshake
	hsData := reflex.MarshalClientHandshake(clientHS)

	// Send: magic + length + data
	request := make([]byte, 4+2+len(hsData))
	binary.BigEndian.PutUint32(request[0:4], reflex.ReflexMagic)
	binary.BigEndian.PutUint16(request[4:6], uint16(len(hsData)))
	copy(request[6:], hsData)

	// Set write deadline
	if err := conn.SetDeadline(time.Now().Add(reflex.HandshakeTimeout)); err != nil {
		return nil, newError("failed to set deadline").Base(err)
	}

	if _, err := conn.Write(request); err != nil {
		return nil, newError("failed to send handshake").Base(err)
	}

	// Read response header
	respHeader := make([]byte, 6)
	if _, err := io.ReadFull(conn, respHeader); err != nil {
		return nil, newError("failed to read response header").Base(err)
	}

	respMagic := binary.BigEndian.Uint32(respHeader[0:4])
	if respMagic != reflex.ReflexMagic {
		return nil, newError("invalid response magic")
	}

	respLen := binary.BigEndian.Uint16(respHeader[4:6])
	if respLen > 4096 {
		return nil, newError("response data too large")
	}

	// Read response data
	respData := make([]byte, respLen)
	if _, err := io.ReadFull(conn, respData); err != nil {
		return nil, newError("failed to read response data").Base(err)
	}

	// Parse server handshake
	serverHS, err := reflex.UnmarshalServerHandshake(respData)
	if err != nil {
		return nil, newError("failed to unmarshal server handshake").Base(err)
	}

	// Validate server timestamp
	if !reflex.ValidateTimestamp(serverHS.Timestamp) {
		return nil, newError("invalid server timestamp")
	}

	// Derive shared key
	sharedKey, err := reflex.DeriveSharedKey(clientPriv, serverHS.PublicKey)
	if err != nil {
		return nil, newError("failed to derive shared key").Base(err)
	}

	// Use timestamp as server nonce (placeholder)
	var serverNonce [16]byte
	binary.BigEndian.PutUint64(serverNonce[0:8], uint64(serverHS.Timestamp))
	binary.BigEndian.PutUint64(serverNonce[8:16], uint64(serverHS.Timestamp))

	// Derive session keys
	sessionKeys, err := reflex.DeriveSessionKeys(sharedKey, clientNonce, serverNonce)
	if err != nil {
		return nil, newError("failed to derive session keys").Base(err)
	}

	// Clear deadlines
	conn.SetDeadline(time.Time{})

	return sessionKeys, nil
}

// handleUplink handles client → server data flow
func (h *Handler) handleUplink(ctx context.Context, reader buf.Reader, writer io.Writer, keys *reflex.SessionKeys) error {
	// TODO: Step 3 - Implement encryption
	if err := buf.Copy(reader, buf.NewWriter(writer)); err != nil {
		return newError("failed to transfer uplink data").Base(err)
	}
	return nil
}

// handleDownlink handles server → client data flow
func (h *Handler) handleDownlink(ctx context.Context, writer buf.Writer, reader io.Reader, keys *reflex.SessionKeys) error {
	// TODO: Step 3 - Implement decryption
	if err := buf.Copy(buf.NewReader(reader), writer); err != nil {
		return newError("failed to transfer downlink data").Base(err)
	}
	return nil
}

// newError creates error with context
func newError(values ...interface{}) *errors.Error {
	return errors.New(values...).AtWarning()
}

func init() {
	common.Must(common.RegisterConfig((*reflex.OutboundConfig)(nil),
		func(ctx context.Context, config interface{}) (interface{}, error) {
			return New(ctx, config.(*reflex.OutboundConfig))
		}))
}
