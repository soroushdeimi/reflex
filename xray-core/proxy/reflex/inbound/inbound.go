package inbound

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"golang.org/x/crypto/curve25519"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// Handler is the inbound handler for Reflex protocol
type Handler struct {
	clients  []*protocol.MemoryUser
	fallback *FallbackConfig
	profile  *reflex.TrafficProfile
}

// FallbackConfig stores fallback configuration
type FallbackConfig struct {
	Dest string // Destination address:port
}

// New creates a new Reflex inbound handler
func New(ctx context.Context, config *reflex.InboundConfig) (*Handler, error) {
	h := &Handler{
		clients: make([]*protocol.MemoryUser, 0),
	}
	
	// Load clients
	for _, user := range config.Clients {
		u := &protocol.MemoryUser{
			Email: user.Id,
			Level: 0,
		}
		account := &reflex.MemoryAccount{
			ID:     user.Id,
			Policy: user.Policy,
		}
		u.Account = account
		h.clients = append(h.clients, u)
	}
	
	// Load fallback config
	if config.Fallback != nil {
		h.fallback = &FallbackConfig{
			Dest: config.Fallback.Addr,
		}
		if h.fallback.Dest == "" && config.Fallback.Dest > 0 {
			h.fallback.Dest = fmt.Sprintf("127.0.0.1:%d", config.Fallback.Dest)
		}
	}
	
	return h, nil
}

// Network returns supported networks
func (h *Handler) Network() []xnet.Network {
	return []xnet.Network{xnet.Network_TCP}
}

// Process handles incoming connections
func (h *Handler) Process(ctx context.Context, network xnet.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	sessionPolicy := session.PolicyFromContext(ctx)
	if sessionPolicy == nil || sessionPolicy.Timeouts.Handshake == 0 {
		// Set default timeout
		conn.SetReadDeadline(time.Now().Add(time.Second * 30))
	} else {
		conn.SetReadDeadline(time.Now().Add(sessionPolicy.Timeouts.Handshake))
	}
	
	// Wrap connection in buffered reader for peeking
	reader := bufio.NewReaderSize(conn, 4096)
	
	// Peek first few bytes to detect protocol
	peeked, err := reader.Peek(64)
	if err != nil && err != io.EOF {
		return newError("failed to peek connection").Base(err)
	}
	
	// Check if it's a Reflex handshake
	if len(peeked) >= 4 {
		magic := binary.BigEndian.Uint32(peeked[0:4])
		if magic == reflex.ReflexMagic {
			// Clear timeout after detection
			conn.SetReadDeadline(time.Time{})
			return h.handleReflexConnection(ctx, reader, conn, dispatcher)
		}
	}
	
	// Not Reflex - fallback to web server
	return h.handleFallback(ctx, reader, conn)
}

// handleReflexConnection processes a Reflex protocol connection
func (h *Handler) handleReflexConnection(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher) error {
	// Read client handshake
	clientHandshake, err := reflex.ReadClientHandshake(reader)
	if err != nil {
		return newError("failed to read client handshake").Base(err)
	}
	
	// Authenticate user
	user, err := h.authenticateUser(clientHandshake.UserID)
	if err != nil {
		return newError("authentication failed").Base(err)
	}
	
	// Generate server key pair
	var serverPrivateKey, serverPublicKey [32]byte
	if _, err := io.ReadFull(rand.Reader, serverPrivateKey[:]); err != nil {
		return newError("failed to generate server key").Base(err)
	}
	
	// Compute server public key using X25519
	curve25519.ScalarBaseMult(&serverPublicKey, &serverPrivateKey)
	
	// Derive shared key
	sharedKey := reflex.DeriveSharedKey(&serverPrivateKey, &clientHandshake.PublicKey)
	
	// Derive session key
	salt := make([]byte, 16)
	copy(salt, clientHandshake.Nonce[:])
	sessionKey := reflex.DeriveSessionKey(sharedKey, salt)
	
	// Send server handshake
	serverHandshake := &reflex.ServerHandshake{
		PublicKey:   serverPublicKey,
		PolicyGrant: []byte(user.Account.(*reflex.MemoryAccount).Policy),
	}
	
	if err := serverHandshake.Write(conn); err != nil {
		return newError("failed to write server handshake").Base(err)
	}
	
	// Create session
	sess, err := reflex.NewSession(sessionKey)
	if err != nil {
		return newError("failed to create session").Base(err)
	}
	
	// Get traffic profile
	policy := user.Account.(*reflex.MemoryAccount).Policy
	if policy == "" {
		policy = "http2-api"
	}
	profile := reflex.GetProfile(policy)
	
	// Start proxying
	return h.proxyConnection(ctx, sess, reader, conn, dispatcher, profile)
}

// authenticateUser checks if the user ID is valid
func (h *Handler) authenticateUser(userID [16]byte) (*protocol.MemoryUser, error) {
	userUUID, err := uuid.ParseBytes(userID[:])
	if err != nil {
		return nil, errors.New("invalid UUID format")
	}
	
	for _, user := range h.clients {
		account := user.Account.(*reflex.MemoryAccount)
		clientUUID, err := uuid.ParseString(account.ID)
		if err != nil {
			continue
		}
		if userUUID.Equals(clientUUID) {
			return user, nil
		}
	}
	
	return nil, errors.New("user not found")
}

// proxyConnection handles bidirectional proxying
func (h *Handler) proxyConnection(ctx context.Context, sess *reflex.Session, reader io.Reader, conn stat.Connection, dispatcher routing.Dispatcher, profile *reflex.TrafficProfile) error {
	// Extract destination from first DATA frame
	frame, err := sess.ReadFrame(reader)
	if err != nil {
		return newError("failed to read first frame").Base(err)
	}
	
	if frame.Type != reflex.FrameTypeData {
		return newError("expected DATA frame, got type ", frame.Type)
	}
	
	// TODO: Parse destination from frame payload properly
	// In a full implementation, the first frame should contain the destination address:port
	// For now, we extract it from the session context or use a default
	// This is a simplified implementation for the course project
	inbound := session.InboundFromContext(ctx)
	dest := xnet.TCPDestination(xnet.DomainAddress("www.google.com"), 80)
	if inbound != nil && inbound.Source.IsValid() {
		// In reality, client should send destination in first frame
		// Format: [address_type][address][port]
		// For this implementation, we'll forward to a test destination
		dest = xnet.TCPDestination(xnet.DomainAddress("www.google.com"), 80)
	}
	
	// Create outbound connection
	link, err := dispatcher.Dispatch(ctx, dest)
	if err != nil {
		return newError("failed to dispatch connection").Base(err)
	}
	defer common.Close(link.Writer)
	
	// Write first data frame to outbound
	if len(frame.Payload) > 0 {
		payload := buf.New()
		payload.Write(frame.Payload)
		if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{payload}); err != nil {
			return newError("failed to write initial data").Base(err)
		}
	}
	
	// Start bidirectional relay
	requestDone := signal.ExecuteAsync(func() error {
		return h.relayClientToServer(sess, reader, link.Writer)
	})
	
	responseDone := signal.ExecuteAsync(func() error {
		return h.relayServerToClient(sess, conn, link.Reader, profile)
	})
	
	if err := task.Run(ctx, task.OnSuccess(requestDone, task.Close(link.Writer)), responseDone); err != nil {
		return newError("connection ended").Base(err)
	}
	
	return nil
}

// relayClientToServer relays data from client to server
func (h *Handler) relayClientToServer(sess *reflex.Session, reader io.Reader, writer buf.Writer) error {
	for {
		frame, err := sess.ReadFrame(reader)
		if err != nil {
			return err
		}
		
		switch frame.Type {
		case reflex.FrameTypeData:
			if len(frame.Payload) > 0 {
				payload := buf.New()
				payload.Write(frame.Payload)
				if err := writer.WriteMultiBuffer(buf.MultiBuffer{payload}); err != nil {
					return err
				}
			}
		case reflex.FrameTypeClose:
			return nil
		case reflex.FrameTypePadding, reflex.FrameTypeTiming:
			// Ignore control frames
			continue
		}
	}
}

// relayServerToClient relays data from server to client with traffic morphing
func (h *Handler) relayServerToClient(sess *reflex.Session, writer io.Writer, reader buf.Reader, profile *reflex.TrafficProfile) error {
	for {
		mb, err := reader.ReadMultiBuffer()
		if err != nil {
			return err
		}
		
		for _, b := range mb {
			data := b.Bytes()
			
			// Apply traffic morphing
			if profile != nil {
				// Respect profile's packet size
				targetSize := profile.GetPacketSize()
				delay := profile.GetDelay()
				
				// Apply delay
				if delay > 0 {
					time.Sleep(delay)
				}
				
				// Chunk data if larger than target size
				for len(data) > 0 {
					chunkSize := targetSize
					if len(data) < chunkSize {
						chunkSize = len(data)
					}
					
					chunk := data[:chunkSize]
					if err := sess.WriteFrame(writer, reflex.FrameTypeData, chunk); err != nil {
						return err
					}
					
					data = data[chunkSize:]
				}
			} else {
				// No morphing - write as is
				if err := sess.WriteFrame(writer, reflex.FrameTypeData, data); err != nil {
					return err
				}
			}
		}
		buf.ReleaseMulti(mb)
	}
}

// handleFallback forwards connection to fallback destination
func (h *Handler) handleFallback(ctx context.Context, reader *bufio.Reader, conn stat.Connection) error {
	if h.fallback == nil {
		return newError("no fallback configured")
	}
	
	// Connect to fallback destination
	dialer := &net.Dialer{}
	fallbackConn, err := dialer.DialContext(ctx, "tcp", h.fallback.Dest)
	if err != nil {
		return newError("failed to connect to fallback").Base(err)
	}
	defer fallbackConn.Close()
	
	// Relay bidirectionally
	errChan := make(chan error, 2)
	
	// Client to fallback
	go func() {
		_, err := io.Copy(fallbackConn, reader)
		errChan <- err
	}()
	
	// Fallback to client
	go func() {
		_, err := io.Copy(conn, fallbackConn)
		errChan <- err
	}()
	
	// Wait for either direction to complete
	return <-errChan
}

func init() {
	common.Must(common.RegisterConfig((*reflex.InboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*reflex.InboundConfig))
	}))
}
