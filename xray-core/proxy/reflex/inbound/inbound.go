package inbound

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/proxy/reflex/encoding"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func init() {
	newError("Reflex inbound init() called - registering handler").AtInfo()
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		newError("Reflex inbound config handler called").AtInfo()
		h, err := New(ctx, config.(*Config))
		if err != nil {
			newError("Reflex inbound New() failed: ", err).AtError()
		} else {
			newError("Reflex inbound New() succeeded").AtInfo()
		}
		return h, err
	}))
	newError("Reflex inbound init() completed").AtInfo()
}

func logToFile(msg string) {
	f, err := os.OpenFile("reflex-inbound-init.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	f.WriteString(msg + "\n")
}

// Handler is an inbound connection handler for Reflex protocol
type Handler struct {
	policyManager policy.Manager
	validator     *reflex.Validator
	fallbacks     map[string]map[string]map[string]*Fallback
}

// New creates a new Reflex inbound handler
func New(ctx context.Context, config *Config) (*Handler, error) {
	newError("Reflex inbound New() called").AtInfo()

	v := core.MustFromContext(ctx)
	handler := &Handler{
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
		validator:     reflex.NewValidator(),
	}
	newError("Reflex handler created, clients count: ", len(config.Clients)).AtInfo()

	// Add users to validator
	for i, user := range config.Clients {
		newError("Processing client ", i, ": ", user).AtInfo()
		mUser, err := user.ToMemoryUser()
		if err != nil {
			newError("Failed to convert user: ", err).AtError()
			return nil, errors.New("failed to get Reflex user").Base(err).AtError()
		}
		newError("Converted user to memory user: ", mUser.Email).AtInfo()
		if err := handler.validator.Add(mUser); err != nil {
			newError("Failed to add user to validator: ", err).AtError()
			return nil, errors.New("failed to add user").Base(err).AtError()
		}
		newError("Added user to validator: ", mUser.Email).AtInfo()
	}

	// Setup fallbacks
	if config.Fallbacks != nil {
		newError("Setting up ", len(config.Fallbacks), " fallbacks").AtInfo()
		handler.fallbacks = make(map[string]map[string]map[string]*Fallback)
		for _, fb := range config.Fallbacks {
			if handler.fallbacks[fb.Name] == nil {
				handler.fallbacks[fb.Name] = make(map[string]map[string]*Fallback)
			}
			if handler.fallbacks[fb.Name][fb.Alpn] == nil {
				handler.fallbacks[fb.Name][fb.Alpn] = make(map[string]*Fallback)
			}
			handler.fallbacks[fb.Name][fb.Alpn][fb.Path] = fb
		}
	}

	newError("Reflex inbound New() completed successfully").AtInfo()
	return handler, nil
}

// Network returns supported networks
func (*Handler) Network() []net.Network {
	return []net.Network{net.Network_TCP, net.Network_UNIX}
}

// Process handles incoming connections
func (h *Handler) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	newError("Reflex inbound connection from ", conn.RemoteAddr()).AtInfo()
	sessionPolicy := h.policyManager.ForLevel(0)

	if err := conn.SetReadDeadline(time.Now().Add(sessionPolicy.Timeouts.Handshake)); err != nil {
		return errors.New("failed to set read deadline").Base(err).AtError()
	}

	// Wrap connection in buffered reader for peeking
	reader := bufio.NewReader(conn)

	// Peek first bytes to check if it's a Reflex handshake
	peeked, err := reader.Peek(76) // Minimum size for handshake with magic
	if err != nil && err != io.EOF {
		return errors.New("failed to peek connection").Base(err).AtError()
	}

	// Check for Reflex magic number
	if len(peeked) >= 4 {
		magic := binary.BigEndian.Uint32(peeked[0:4])
		if magic == encoding.ReflexMagic {
			return h.handleReflexHandshake(ctx, reader, conn, dispatcher, sessionPolicy)
		}
	}

	// Not a Reflex connection - fallback
	return h.handleFallback(ctx, reader, conn)
}

// handleReflexHandshake processes the Reflex handshake
func (h *Handler) handleReflexHandshake(
	ctx context.Context,
	reader *bufio.Reader,
	conn stat.Connection,
	dispatcher routing.Dispatcher,
	sessionPolicy policy.Session,
) error {
	// Read handshake packet (76 bytes) - use pooled buffer
	handshakeData := encoding.GetClientHandshakeBuffer()
	defer encoding.PutClientHandshakeBuffer(handshakeData)
	if _, err := io.ReadFull(reader, handshakeData); err != nil {
		return errors.New("failed to read handshake").Base(err).AtError()
	}

	// Decode client handshake
	clientHS, err := encoding.DecodeClientHandshake(handshakeData)
	if err != nil {
		return errors.New("invalid handshake").Base(err).AtError()
	}

	// Validate timestamp
	if !encoding.ValidateTimestamp(clientHS.Timestamp) {
		return errors.New("invalid timestamp").AtError()
	}

	// Find and authenticate user
	account, err := h.validator.Get(clientHS.UserID)
	if err != nil {
		newError("authentication failed: ", err).AtWarning()
		return h.handleFallback(ctx, reader, conn)
	}

	// Generate server key pair
	serverPrivateKey, serverPublicKey, err := encoding.GenerateKeyPair()
	if err != nil {
		return errors.New("failed to generate key pair").Base(err).AtError()
	}

	// Derive shared key and session key
	sharedKey := encoding.DeriveSharedKey(serverPrivateKey, clientHS.PublicKey)
	sessionKey, err := encoding.DeriveSessionKey(sharedKey, []byte("reflex-session-v1"))
	if err != nil {
		return errors.New("failed to derive session key").Base(err).AtError()
	}

	// Send server handshake response (use pooled buffer)
	serverHS := &encoding.ServerHandshake{
		PublicKey: serverPublicKey,
		Timestamp: time.Now().Unix(),
	}
	responseData := encoding.EncodeServerHandshake(serverHS)
	defer encoding.PutServerHandshakeBuffer(responseData)
	if _, err := conn.Write(responseData); err != nil {
		return errors.New("failed to send handshake response").Base(err).AtError()
	}

	// Clear handshake deadline
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return errors.New("failed to clear read deadline").Base(err).AtError()
	}

	newError("handshake completed for user: ", account.Email).AtInfo()
	logToFile("HANDSHAKE COMPLETED for user: " + account.Email)

	// Create frame encoder/decoder
	frameEncoder, err := encoding.NewFrameEncoder(sessionKey)
	if err != nil {
		return errors.New("failed to create frame encoder").Base(err).AtError()
	}

	frameDecoder, err := encoding.NewFrameDecoder(sessionKey)
	if err != nil {
		return errors.New("failed to create frame decoder").Base(err).AtError()
	}

	// Read first data frame to get request header
	firstFrame, err := frameDecoder.ReadFrame(reader)
	if err != nil {
		return errors.New("failed to read first frame").Base(err).AtError()
	}

	if firstFrame.Type != encoding.FrameTypeData {
		return errors.New("expected data frame").AtError()
	}

	// Parse request header from frame payload
	request, err := parseRequestHeader(firstFrame.Payload)
	if err != nil {
		return errors.New("failed to parse request").Base(err).AtError()
	}

	// Update session context
	inbound := session.InboundFromContext(ctx)
	if inbound == nil {
		inbound = &session.Inbound{}
		ctx = session.ContextWithInbound(ctx, inbound)
	}
	inbound.User = account

	// Get user policy
	userLevel := uint32(0)
	if account != nil {
		userLevel = account.Level
	}
	ctx = policy.ContextWithBufferPolicy(ctx, sessionPolicy.Buffer)
	sessionPolicy = h.policyManager.ForLevel(userLevel)

	// Setup dispatcher link
	ctx, cancel := context.WithCancel(ctx)
	_ = cancel  // Keep for now but don't defer it - let responseDone signal completion

	link, err := dispatcher.Dispatch(ctx, request.Destination())
	if err != nil {
		return errors.New("failed to dispatch request").Base(err).AtError()
	}

	// Transfer data
	requestDone := func() error {
		logToFile(fmt.Sprintf("requestDone: First frame payload size: %d bytes", len(firstFrame.Payload)))
		// Write first frame data to link (zero-copy with FromBytes)
		if len(firstFrame.Payload) > 12 { // After header
			headerSize := 12 // Simplified: command(1) + port(2) + address(variable, ~9)
			if headerSize < len(firstFrame.Payload) {
				// Use FromBytes to avoid allocation (unmanaged buffer)
				payload := buf.FromBytes(firstFrame.Payload[headerSize:])
				logToFile(fmt.Sprintf("requestDone: Sending %d bytes from first frame to link.Writer", len(firstFrame.Payload[headerSize:])))
				if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{payload}); err != nil {
					logToFile(fmt.Sprintf("requestDone: WriteMultiBuffer error on first frame: %v", err))
					return err
				}
				logToFile("requestDone: First frame data sent successfully")
			}
		}
		// Return frame struct to pool after first frame is processed
		defer encoding.PutFrame(firstFrame)

		// Read subsequent frames and write to dispatcher
		logToFile("requestDone: Starting to read subsequent frames from client")
		for {
			frame, err := frameDecoder.ReadFrame(reader)
			if err != nil {
				logToFile(fmt.Sprintf("requestDone: ReadFrame error: %v", err))
				return err
			}
			logToFile(fmt.Sprintf("requestDone: Got frame type %d with %d bytes", frame.Type, len(frame.Payload)))

			switch frame.Type {
			case encoding.FrameTypeData:
				// Use FromBytes to avoid allocation (unmanaged buffer - zero-copy)
				payload := buf.FromBytes(frame.Payload)
				if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{payload}); err != nil {
					encoding.PutFrame(frame)
					return err
				}
				// Return frame struct to pool after payload is written
				encoding.PutFrame(frame)
			case encoding.FrameTypeClose:
				logToFile("requestDone: Received close frame from client, returning")
				encoding.PutFrame(frame)
				return nil
			case encoding.FrameTypePadding, encoding.FrameTypeTiming:
				// Control frames - ignore for now
				encoding.PutFrame(frame)
				continue
			default:
				encoding.PutFrame(frame)
				return errors.New("unknown frame type: ", frame.Type).AtWarning()
			}
		}
	}

	responseDone := func() error {
		newError("responseDone: Starting to read from dispatcher").AtInfo()
		// Read from dispatcher and write as frames
		for {
			newError("responseDone: Waiting for response from dispatcher...").AtDebug()
			mb, err := link.Reader.ReadMultiBuffer()
			if err != nil {
				newError("responseDone: ReadMultiBuffer error: ", err).AtWarning()
				// Send close frame to signal end of response
				closeFrame := &encoding.Frame{
					Type: encoding.FrameTypeClose,
				}
				frameEncoder.WriteFrame(conn, closeFrame)
				return err
			}

			newError(fmt.Sprintf("responseDone: Got %d buffers from dispatcher", len(mb))).AtDebug()
			for i, b := range mb {
				newError(fmt.Sprintf("responseDone: Buffer %d has %d bytes", i, len(b.Bytes()))).AtDebug()
				frame := &encoding.Frame{
					Type:    encoding.FrameTypeData,
					Payload: b.Bytes(),
				}
				if err := frameEncoder.WriteFrame(conn, frame); err != nil {
					newError("responseDone: WriteFrame error: ", err).AtWarning()
					buf.ReleaseMulti(mb)
					return err
				}
				newError(fmt.Sprintf("responseDone: Sent %d bytes back to client", len(b.Bytes()))).AtDebug()
			}
			buf.ReleaseMulti(mb)
		}
	}

	// Run both directions concurrently
	if err := task.Run(ctx, requestDone, responseDone); err != nil {
		return errors.New("connection ends").Base(err).AtInfo()
	}

	return nil
}

// parseRequestHeader parses request header from frame payload
// Simplified version - format: [command(1)] + [port(2)] + [address]
func parseRequestHeader(payload []byte) (*protocol.RequestHeader, error) {
	if len(payload) < 4 {
		return nil, errors.New("payload too short")
	}

	request := &protocol.RequestHeader{
		Version: 1,
		Command: protocol.RequestCommand(payload[0]),
	}

	// Parse port
	request.Port = net.PortFromBytes(payload[1:3])

	// Parse address (simplified - assumes IPv4 for now)
	if len(payload) >= 7 {
		addrType := payload[3]
		switch addrType {
		case 1: // IPv4
			if len(payload) < 8 {
				return nil, errors.New("invalid IPv4 address")
			}
			request.Address = net.IPAddress(payload[4:8])
		case 3: // Domain
			if len(payload) < 5 {
				return nil, errors.New("invalid domain address")
			}
			domainLen := int(payload[4])
			if len(payload) < 5+domainLen {
				return nil, errors.New("incomplete domain address")
			}
			request.Address = net.DomainAddress(string(payload[5 : 5+domainLen]))
		case 4: // IPv6
			if len(payload) < 20 {
				return nil, errors.New("invalid IPv6 address")
			}
			request.Address = net.IPAddress(payload[4:20])
		default:
			return nil, errors.New("unknown address type: ", addrType)
		}
	}

	return request, nil
}

func newError(values ...interface{}) *errors.Error {
	return errors.New(values...)
}
