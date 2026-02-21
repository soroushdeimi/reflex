package inbound

import (
	"bufio"
	"context"
	"crypto/hmac"
	"encoding/binary"
	"fmt"
	"io"
	stdnet "net"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport/internet/stat"
	"google.golang.org/protobuf/proto"
)

// Handler implements proxy.Inbound interface for Reflex protocol.
// It handles incoming connections and processes Reflex protocol messages.
type Handler struct {
	clients   []*protocol.MemoryUser
	fallback  *FallbackConfig
	userUUIDs []string            // Cached UUID list for quick lookup
	userPolicies map[string]string // Map UUID to policy (traffic profile name)
}

// MemoryAccount implements protocol.Account interface for Reflex users.
// It stores user identification (UUID) for authentication.
type MemoryAccount struct {
	Id string
}

// Equals implements protocol.Account interface.
// Compares two Reflex accounts by their UUID.
func (a *MemoryAccount) Equals(account protocol.Account) bool {
	reflexAccount, ok := account.(*MemoryAccount)
	if !ok {
		return false
	}
	return a.Id == reflexAccount.Id
}

// ToProto implements protocol.Account interface.
// Converts MemoryAccount to protobuf message.
func (a *MemoryAccount) ToProto() proto.Message {
	return &reflex.Account{
		Id: a.Id,
	}
}

// FallbackConfig stores fallback destination configuration.
// Used when connection doesn't match Reflex protocol.
type FallbackConfig struct {
	Dest uint32 // Destination port for fallback
}

// Network returns list of networks supported by this handler.
// Currently only TCP is supported.
func (h *Handler) Network() []net.Network {
	return []net.Network{net.Network_TCP}
}

// Process handles incoming connections and performs handshake
func (h *Handler) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	reader := bufio.NewReader(conn)

	// Peek to detect protocol (without consuming bytes)
	peeked, err := reader.Peek(reflex.HandshakeSize)
	if err != nil {
		return errors.New("failed to read handshake").Base(err)
	}

	// Check for Reflex magic number
	if len(peeked) < 4 {
		return errors.New("connection closed unexpectedly")
	}

	// Detect protocol using fallback detector hook
	detector := reflex.NewFallbackDetector(h.fallback != nil)
	if detector.ShouldFallback(peeked) {
		// Fallback to web server
		if h.fallback == nil {
			return errors.New("non-Reflex protocol detected - no fallback configured")
		}
		return h.handleFallback(ctx, reader, conn)
	}

	return h.handleHandshake(ctx, reader, conn, dispatcher)
}

// handleHandshake processes the Reflex handshake
func (h *Handler) handleHandshake(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher) error {
	// Read handshake packet
	handshakeData := make([]byte, reflex.HandshakeSize)
	if _, err := io.ReadFull(reader, handshakeData); err != nil {
		return errors.New("failed to read handshake packet").Base(err)
	}

	// Decode client handshake
	clientHS, err := reflex.DecodeClientHandshake(handshakeData)
	if err != nil {
		return errors.New("invalid handshake format").Base(err)
	}

	// Verify timestamp (prevent replay attacks)
	if !reflex.VerifyTimestamp(clientHS.Timestamp) {
		return errors.New("handshake timestamp out of range")
	}

	// Authenticate user
	userUUID, err := reflex.AuthenticateUser(clientHS.UserID, h.userUUIDs)
	if err != nil {
		log.Record(&log.GeneralMessage{
			Severity: log.Severity_Warning,
			Content:  "Reflex: Authentication failed - user not found",
		})
		return errors.New("authentication failed").Base(err)
	}

	// Get shared secret for HMAC verification
	secret, err := reflex.GetSharedSecret(userUUID)
	if err != nil {
		return errors.New("failed to get shared secret").Base(err)
	}

	// Verify client HMAC
	expectedHMAC := reflex.ComputeClientHMAC(
		secret,
		clientHS.Version,
		clientHS.PublicKey,
		clientHS.UserID,
		clientHS.Timestamp,
		clientHS.Nonce,
	)
	if !hmac.Equal(clientHS.HMAC[:], expectedHMAC[:]) {
		log.Record(&log.GeneralMessage{
			Severity: log.Severity_Warning,
			Content:  "Reflex: Authentication failed - invalid HMAC",
		})
		return errors.New("authentication failed - invalid HMAC")
	}

	// Generate server key pair
	serverPrivateKey, serverPublicKey, err := reflex.GenerateKeyPair()
	if err != nil {
		return errors.New("failed to generate server key pair").Base(err)
	}

	// Derive shared secret
	sharedKey := reflex.DeriveSharedKey(serverPrivateKey, clientHS.PublicKey)

	// Derive session key (for future use in Step 3)
	sessionKey := reflex.DeriveSessionKey(sharedKey, []byte("reflex-session"))

	// Compute server HMAC
	serverHMAC := reflex.ComputeServerHMAC(secret, reflex.HandshakeVersion, serverPublicKey)

	// Create and send server handshake
	serverHS := &reflex.ServerHandshake{
		Version:   reflex.HandshakeVersion,
		PublicKey: serverPublicKey,
		HMAC:      serverHMAC,
	}

	response := reflex.EncodeServerHandshake(serverHS)
	if _, err := conn.Write(response); err != nil {
		return errors.New("failed to send server handshake").Base(err)
	}

	log.Record(&log.GeneralMessage{
		Severity: log.Severity_Info,
		Content:  "Reflex: Handshake completed successfully",
	})

	// Find user object
	var user *protocol.MemoryUser
	for _, u := range h.clients {
		if u.Account.(*MemoryAccount).Id == userUUID {
			user = u
			break
		}
	}

	// Get traffic profile from user policy (if specified)
	var profile *reflex.TrafficProfile
	if user != nil {
		// Get policy from user UUID
		if policyName, ok := h.userPolicies[userUUID]; ok && policyName != "" {
			profile = reflex.GetProfile(policyName)
			if profile == nil {
				log.Record(&log.GeneralMessage{
					Severity: log.Severity_Warning,
					Content:  "Reflex: Unknown traffic profile: " + policyName,
				})
			}
		}
	}

	// Create encryption session with profile
	var session *reflex.Session
	if profile != nil {
		session, err = reflex.NewSessionWithProfile(sessionKey, reflex.DefaultMorphingConfig(), profile)
	} else {
		session, err = reflex.NewSession(sessionKey)
	}
	if err != nil {
		return errors.New("failed to create session").Base(err)
	}

	// Process encrypted frames
	return h.handleSession(ctx, reader, conn, dispatcher, session, user)
}

// handleSession processes encrypted frames after handshake
func (h *Handler) handleSession(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, session *reflex.Session, user *protocol.MemoryUser) error {
	for {
		frame, err := session.ReadFrame(reader)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return errors.New("failed to read frame").Base(err)
		}

		// Validate frame payload size (drop suspicious packets)
		if !reflex.ValidatePacketSize(len(frame.Payload), session.GetMorphingConfig()) {
			return errors.New("suspicious packet size detected")
		}

		switch frame.Type {
		case reflex.FrameTypeData:
			// Forward user data to upstream
			if err := h.handleDataFrame(ctx, frame.Payload, conn, dispatcher, session); err != nil {
				return err
			}

		case reflex.FrameTypePadding:
			// Padding control - handle control frame
			if err := session.HandleControlFrame(frame); err != nil {
				return errors.New("failed to handle padding control").Base(err)
			}
			continue

		case reflex.FrameTypeTiming:
			// Timing control - handle control frame
			if err := session.HandleControlFrame(frame); err != nil {
				return errors.New("failed to handle timing control").Base(err)
			}
			continue

		case reflex.FrameTypeClose:
			// Close connection
			return nil

		default:
			return errors.New("unknown frame type")
		}
	}
}

// handleDataFrame forwards decrypted data to upstream
func (h *Handler) handleDataFrame(ctx context.Context, data []byte, conn stat.Connection, dispatcher routing.Dispatcher, session *reflex.Session) error {
	if len(data) < 3 {
		return errors.New("invalid data frame")
	}

	// Parse destination from payload (simple format: address length + address + port)
	addrLen := int(data[0])
	if addrLen == 0 || len(data) < 1+addrLen+2 {
		return errors.New("invalid destination format")
	}

	address := string(data[1 : 1+addrLen])
	port := net.Port(binary.BigEndian.Uint16(data[1+addrLen:]))

	dest := net.TCPDestination(net.ParseAddress(address), port)
	link, err := dispatcher.Dispatch(ctx, dest)
	if err != nil {
		return errors.New("failed to dispatch").Base(err)
	}

	// Forward remaining data to upstream
	payload := data[1+addrLen+2:]
	if len(payload) > 0 {
		buffer := buf.FromBytes(payload)
		if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{buffer}); err != nil {
			return err
		}
	}

	// Forward responses from upstream to client
	go func() {
		defer common.Close(link.Writer)
		for {
			mb, err := link.Reader.ReadMultiBuffer()
			if err != nil {
				return
			}
			for _, b := range mb {
				if err := session.WriteFrame(conn, reflex.FrameTypeData, b.Bytes()); err != nil {
					return
				}
				b.Release()
			}
		}
	}()

	return nil
}

// preloadedConn wraps bufio.Reader to handle peeked bytes
type preloadedConn struct {
	*bufio.Reader
	stat.Connection
}

// Read reads from the buffered reader (includes peeked bytes)
func (pc *preloadedConn) Read(b []byte) (int, error) {
	return pc.Reader.Read(b)
}

// Write writes to the underlying connection
func (pc *preloadedConn) Write(b []byte) (int, error) {
	return pc.Connection.Write(b)
}

// handleFallback forwards connection to fallback web server
func (h *Handler) handleFallback(ctx context.Context, reader *bufio.Reader, conn stat.Connection) error {
	if h.fallback == nil {
		return errors.New("no fallback configured")
	}

	log.Record(&log.GeneralMessage{
		Severity: log.Severity_Info,
		Content:  fmt.Sprintf("Reflex: Fallback to web server on port %d", h.fallback.Dest),
	})

	// Create preloaded connection wrapper to handle peeked bytes
	wrappedConn := &preloadedConn{
		Reader:     reader,
		Connection: conn,
	}

	// Connect to fallback web server
	targetAddr := fmt.Sprintf("127.0.0.1:%d", h.fallback.Dest)
	dialer := stdnet.Dialer{}
	target, err := dialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		return errors.New("failed to connect to fallback server").Base(err)
	}
	defer target.Close()

	// Forward data bidirectionally
	done := make(chan error, 2)

	// Forward from client to web server
	go func() {
		_, err := io.Copy(target, wrappedConn)
		done <- err
	}()

	// Forward from web server to client
	go func() {
		_, err := io.Copy(wrappedConn, target)
		done <- err
	}()

	// Wait for one direction to finish or context cancellation
	select {
	case err := <-done:
		if err != nil && err != io.EOF {
			return errors.New("fallback forwarding error").Base(err)
		}
		// Wait a bit for the other direction to finish gracefully
		select {
		case <-done:
		case <-time.After(100 * time.Millisecond):
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// init registers the Reflex inbound handler with Xray-Core.
// This is called automatically when the package is imported.
func init() {
	common.Must(common.RegisterConfig((*reflex.InboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*reflex.InboundConfig))
	}))
}

// New creates a new Reflex inbound handler from configuration.
// It parses the config, creates user accounts, and sets up fallback if configured.
func New(ctx context.Context, config *reflex.InboundConfig) (proxy.Inbound, error) {
	handler := &Handler{
		clients:      make([]*protocol.MemoryUser, 0),
		userUUIDs:    make([]string, 0),
		userPolicies: make(map[string]string),
	}

	// Convert config clients to MemoryUser objects
	for _, client := range config.Clients {
		handler.clients = append(handler.clients, &protocol.MemoryUser{
			Email:   client.Id,
			Account: &MemoryAccount{Id: client.Id},
		})
		handler.userUUIDs = append(handler.userUUIDs, client.Id)
		// Store policy if specified
		if client.Policy != "" {
			handler.userPolicies[client.Id] = client.Policy
		}
	}

	// Setup fallback if configured
	if config.Fallback != nil {
		handler.fallback = &FallbackConfig{
			Dest: config.Fallback.Dest,
		}
	}

	log.Record(&log.GeneralMessage{
		Severity: log.Severity_Info,
		Content:  "Reflex: Inbound handler initialized",
	})

	return handler, nil
}
