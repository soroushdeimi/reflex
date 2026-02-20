package inbound

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport/internet/stat"
	"google.golang.org/protobuf/proto"
)

// Handler is the inbound handler for Reflex protocol
type Handler struct {
	policyManager   policy.Manager
	validator       *Validator
	fallback        *FallbackConfig
	config          *reflex.InboundConfig
	protocolDet     *reflex.ProtocolDetector
	morphingProfile *reflex.TrafficProfile
	stats           *reflex.TrafficStats
}

// FallbackConfig holds fallback configuration
type FallbackConfig struct {
	Dest uint32
	Path string
}

// Validator manages user authentication
type Validator struct {
	sync.RWMutex
	users map[string]*protocol.MemoryUser
}

// NewValidator creates a new validator
func NewValidator() *Validator {
	return &Validator{
		users: make(map[string]*protocol.MemoryUser),
	}
}

// Add adds a user to validator
func (v *Validator) Add(user *protocol.MemoryUser) error {
	v.Lock()
	defer v.Unlock()

	account := user.Account.(*MemoryAccount)
	v.users[account.ID] = user
	return nil
}

// Get retrieves a user by ID
func (v *Validator) Get(userID string) (*protocol.MemoryUser, bool) {
	v.RLock()
	defer v.RUnlock()

	user, found := v.users[userID]
	return user, found
}

// MemoryAccount implements protocol.Account
type MemoryAccount struct {
	ID     string
	Policy string
}

// Equals compares two accounts
func (a *MemoryAccount) Equals(account protocol.Account) bool {
	reflexAccount, ok := account.(*MemoryAccount)
	if !ok {
		return false
	}
	return a.ID == reflexAccount.ID
}

// ToProto converts to protobuf message
func (a *MemoryAccount) ToProto() proto.Message {
	return &reflex.Account{Id: a.ID}
}

// New creates a new Reflex inbound handler
func New(ctx context.Context, config *reflex.InboundConfig) (*Handler, error) {
	v := core.MustFromContext(ctx)

	handler := &Handler{
		policyManager:   v.GetFeature(policy.ManagerType()).(policy.Manager),
		validator:       NewValidator(),
		config:          config,
		protocolDet:     reflex.NewProtocolDetector(),
		morphingProfile: reflex.GetProfileByName(config.DefaultProfile),
		stats:           reflex.NewTrafficStats(),
	}

	// Add users to validator
	for _, user := range config.Clients {
		u := &protocol.MemoryUser{
			Email: user.Id,
			Account: &MemoryAccount{
				ID:     user.Id,
				Policy: user.Policy,
			},
		}
		if err := handler.validator.Add(u); err != nil {
			return nil, err
		}
	}

	// Setup fallback if configured
	if config.Fallback != nil {
		handler.fallback = &FallbackConfig{
			Dest: config.Fallback.Dest,
			Path: config.Fallback.Path,
		}
	}

	return handler, nil
}

// Network returns supported networks
func (h *Handler) Network() []xnet.Network {
	return []xnet.Network{xnet.Network_TCP}
}

// Process handles incoming connection
func (h *Handler) Process(ctx context.Context, network xnet.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	// Set handshake deadline
	sessionPolicy := h.policyManager.ForLevel(0)
	if err := conn.SetReadDeadline(time.Now().Add(sessionPolicy.Timeouts.Handshake)); err != nil {
		return newError("failed to set read deadline").Base(err)
	}

	// Wrap in buffered reader for peeking
	reader := bufio.NewReaderSize(conn, 4096)

	// Peek first bytes for protocol detection
	peeked, err := reader.Peek(64)
	if err != nil && err != io.EOF {
		return newError("failed to peek data").Base(err)
	}

	// Detect protocol
	protocol := h.protocolDet.DetectProtocol(peeked)

	switch protocol {
	case "reflex":
		// Check if valid handshake
		if h.protocolDet.IsReflexHandshake(peeked) {
			return h.handleReflexHandshake(ctx, reader, conn, dispatcher)
		}
		fallthrough // If invalid, treat as fallback

	default:
		// Not Reflex - fallback to HTTP server
		return h.handleFallback(ctx, reader, conn)
	}
}

// handleReflexHandshake processes Reflex handshake
func (h *Handler) handleReflexHandshake(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher) error {
	// Read magic (already peeked, but consume it)
	var magic uint32
	if err := binary.Read(reader, binary.BigEndian, &magic); err != nil {
		return newError("failed to read magic").Base(err)
	}

	// Read handshake data length
	var dataLen uint16
	if err := binary.Read(reader, binary.BigEndian, &dataLen); err != nil {
		return newError("failed to read data length").Base(err)
	}

	if dataLen > 4096 {
		return newError("handshake data too large: ", dataLen)
	}

	// Read handshake data
	hsData := make([]byte, dataLen)
	if _, err := io.ReadFull(reader, hsData); err != nil {
		return newError("failed to read handshake data").Base(err)
	}

	// Parse client handshake
	clientHS, err := reflex.UnmarshalClientHandshake(hsData)
	if err != nil {
		return newError("failed to unmarshal handshake").Base(err)
	}

	// Validate timestamp
	if !reflex.ValidateTimestamp(clientHS.Timestamp) {
		return newError("invalid timestamp")
	}

	// Authenticate user
	userID := reflex.ParseUUID(clientHS.UserID)
	user, found := h.validator.Get(userID)
	if !found {
		return h.handleFallback(ctx, reader, conn)
	}

	// Generate server key pair
	serverPriv, serverPub, err := reflex.GenerateKeyPair()
	if err != nil {
		return newError("failed to generate key pair").Base(err)
	}

	// Derive shared key
	sharedKey, err := reflex.DeriveSharedKey(serverPriv, clientHS.PublicKey)
	if err != nil {
		return newError("failed to derive shared key").Base(err)
	}

	// Use single timestamp for both nonce and handshake
	ts := time.Now().Unix()

	// Build serverNonce from timestamp (same logic as client)
	var serverNonce [16]byte
	binary.BigEndian.PutUint64(serverNonce[0:8], uint64(ts))
	binary.BigEndian.PutUint64(serverNonce[8:16], uint64(ts))

	// Derive session keys
	sessionKeys, err := reflex.DeriveSessionKeys(sharedKey, clientHS.Nonce, serverNonce)
	if err != nil {
		return newError("failed to derive session keys").Base(err)
	}

	// Create server handshake response
	serverHS := &reflex.ServerHandshake{
		PublicKey:   serverPub,
		Timestamp:   ts,
		PolicyGrant: []byte{},
	}

	// Marshal server handshake
	serverHSData := reflex.MarshalServerHandshake(serverHS)

	// Send response: magic + length + data
	response := make([]byte, 4+2+len(serverHSData))
	binary.BigEndian.PutUint32(response[0:4], reflex.ReflexMagic)
	binary.BigEndian.PutUint16(response[4:6], uint16(len(serverHSData)))
	copy(response[6:], serverHSData)

	if _, err := conn.Write(response); err != nil {
		return newError("failed to send handshake response").Base(err)
	}

	// Clear handshake deadline
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return newError("failed to clear deadline").Base(err)
	}

	// Setup session context
	inbound := session.InboundFromContext(ctx)
	if inbound == nil {
		inbound = &session.Inbound{}
		ctx = session.ContextWithInbound(ctx, inbound)
	}
	inbound.Name = "reflex"
	inbound.User = user

	// Handle session with morphing
	return h.handleSession(ctx, reader, conn, dispatcher, sessionKeys)
}

// handleSession handles established session with encryption and morphing
func (h *Handler) handleSession(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, keys *reflex.SessionKeys) error {
	// Create encrypted session with optional morphing
	var sess *reflex.Session
	var err error

	if h.config.EnableTrafficMorphing && h.morphingProfile != nil {
		sess, err = reflex.NewServerSessionWithMorphing(keys, h.morphingProfile)
	} else {
		sess, err = reflex.NewServerSession(keys)
	}

	if err != nil {
		return newError("failed to create session").Base(err)
	}

	// Read first frame to get destination
	firstFrame, err := sess.ReadFrame(reader, true)
	if err != nil {
		return newError("failed to read first frame").Base(err)
	}

	if firstFrame.Type != reflex.FrameTypeData {
		return newError("first frame must be data frame")
	}

	// Decode destination from payload
	destReader := bytes.NewReader(firstFrame.Payload)
	dest, err := reflex.DecodeDestination(destReader)
	if err != nil {
		return newError("failed to decode destination").Base(err)
	}

	// Dispatch connection
	link, err := dispatcher.Dispatch(ctx, dest)
	if err != nil {
		return newError("failed to dispatch").Base(err)
	}

	// Calculate remaining data after destination
	destBytesLen := len(firstFrame.Payload) - destReader.Len()
	remaining := firstFrame.Payload[destBytesLen:]

	// Send first data chunk if exists
	if len(remaining) > 0 {
		b := buf.FromBytes(remaining)
		if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
			return newError("failed to write first chunk").Base(err)
		}
	}

	// Start bidirectional forwarding
	requestDone := func() error {
		return h.handleUplink(reader, link.Writer, sess)
	}

	responseDone := func() error {
		return h.handleDownlink(conn, link.Reader, sess)
	}

	if err := task.Run(ctx, requestDone, responseDone); err != nil {
		return newError("connection closed").Base(err)
	}

	return nil
}

// handleUplink reads from client and writes to upstream
func (h *Handler) handleUplink(reader *bufio.Reader, writer buf.Writer, sess *reflex.Session) error {
	for {
		frame, err := sess.ReadFrame(reader, true)
		if err != nil {
			return err
		}

		switch frame.Type {
		case reflex.FrameTypeData:
			b := buf.FromBytes(frame.Payload)
			if err := writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
				return newError("failed to write uplink data").Base(err)
			}

			// Record traffic stats if enabled
			if h.config.EnableTrafficMorphing {
				h.stats.RecordPacket(len(frame.Payload), 0)
			}

		case reflex.FrameTypeClose:
			return nil

		case reflex.FrameTypePadding, reflex.FrameTypeTiming:
			// Handle control frames for dynamic morphing
			if err := sess.HandleControlFrame(frame); err != nil {
				return newError("failed to handle control frame").Base(err)
			}
			continue

		default:
			return newError("unknown frame type: ", frame.Type)
		}
	}
}

// handleDownlink reads from upstream and writes to client
func (h *Handler) handleDownlink(conn stat.Connection, reader buf.Reader, sess *reflex.Session) error {
	for {
		mb, err := reader.ReadMultiBuffer()
		if err != nil {
			sess.WriteFrame(conn, reflex.FrameTypeClose, nil, true)
			return nil
		}

		for _, b := range mb {
			var writeErr error

			// Use morphing writer if enabled
			if h.config.EnableTrafficMorphing && sess.IsMorphingEnabled() {
				writeErr = sess.WriteFrameWithMorphing(conn, reflex.FrameTypeData, b.Bytes(), true)
			} else {
				writeErr = sess.WriteFrame(conn, reflex.FrameTypeData, b.Bytes(), true)
			}

			if writeErr != nil {
				b.Release()
				return newError("failed to write downlink data").Base(writeErr)
			}

			// Record traffic stats if enabled
			if h.config.EnableTrafficMorphing {
				h.stats.RecordPacket(len(b.Bytes()), 0)
			}

			b.Release()
		}
	}
}

// handleFallback forwards connection to fallback destination
func (h *Handler) handleFallback(ctx context.Context, reader *bufio.Reader, conn stat.Connection) error {
	if h.fallback == nil {
		return newError("fallback not configured")
	}

	// Create fallback connection wrapper
	fallbackConn := reflex.NewFallbackConn(reader, conn)

	// Dial fallback server
	target, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", h.fallback.Dest))
	if err != nil {
		return newError("failed to dial fallback server").Base(err)
	}
	defer target.Close()

	// Forward connection
	if err := reflex.ForwardConnection(fallbackConn, target); err != nil {
		if err != io.EOF {
			return newError("fallback forwarding error").Base(err)
		}
	}

	return nil
}

// GetTrafficStats returns collected traffic statistics
func (h *Handler) GetTrafficStats() *reflex.TrafficStats {
	return h.stats
}

// SetMorphingProfile sets traffic morphing profile
func (h *Handler) SetMorphingProfile(profile *reflex.TrafficProfile) {
	h.morphingProfile = profile
}

// GetMorphingProfile returns current morphing profile
func (h *Handler) GetMorphingProfile() *reflex.TrafficProfile {
	return h.morphingProfile
}

// newError creates error with context
func newError(values ...interface{}) *errors.Error {
	return errors.New(values...).AtWarning()
}

func init() {
	common.Must(common.RegisterConfig((*reflex.InboundConfig)(nil),
		func(ctx context.Context, config interface{}) (interface{}, error) {
			return New(ctx, config.(*reflex.InboundConfig))
		}))
}
