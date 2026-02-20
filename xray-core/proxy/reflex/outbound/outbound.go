package outbound

import (
	"context"
	"crypto/rand"
	"io"
	"time"

	"golang.org/x/crypto/curve25519"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
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

// Handler is the outbound handler for Reflex protocol
type Handler struct {
	policyManager policy.Manager
	config        *reflex.OutboundConfig
	profile       *reflex.TrafficProfile
}

// New creates a new Reflex outbound handler
func New(ctx context.Context, config *reflex.OutboundConfig) (*Handler, error) {
	v := core.MustFromContext(ctx)
	
	h := &Handler{
		config:        config,
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
	}
	
	// Load traffic profile
	policyName := config.Policy
	if policyName == "" {
		policyName = "http2-api"
	}
	h.profile = reflex.GetProfile(policyName)
	
	return h, nil
}

// Process handles outbound connections
func (h *Handler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbound := session.OutboundFromContext(ctx)
	if outbound == nil || !outbound.Target.IsValid() {
		return newError("target not specified")
	}
	destination := outbound.Target
	
	// Connect to server
	conn, err := dialer.Dial(ctx, net.TCPDestination(net.ParseAddress(h.config.Address), net.Port(h.config.Port)))
	if err != nil {
		return newError("failed to connect to server").Base(err)
	}
	defer conn.Close()
	
	// Perform handshake
	sess, err := h.performHandshake(conn)
	if err != nil {
		return newError("handshake failed").Base(err)
	}
	
	// Start proxying
	requestDone := signal.ExecuteAsync(func() error {
		return h.relayClientToServer(ctx, sess, link.Reader, conn, destination)
	})
	
	responseDone := signal.ExecuteAsync(func() error {
		return h.relayServerToClient(ctx, sess, conn, link.Writer)
	})
	
	if err := task.Run(ctx, task.OnSuccess(requestDone, task.Close(link.Writer)), responseDone); err != nil {
		return newError("connection ended").Base(err)
	}
	
	return nil
}

// performHandshake performs the client handshake
func (h *Handler) performHandshake(conn stat.Connection) (*reflex.Session, error) {
	// Generate client key pair
	var clientPrivateKey, clientPublicKey [32]byte
	if _, err := io.ReadFull(rand.Reader, clientPrivateKey[:]); err != nil {
		return nil, newError("failed to generate client key").Base(err)
	}
	
	// Compute client public key using X25519
	curve25519.ScalarBaseMult(&clientPublicKey, &clientPrivateKey)
	
	// Parse user UUID
	userUUID, err := uuid.ParseString(h.config.Id)
	if err != nil {
		return nil, newError("invalid user ID").Base(err)
	}
	
	// Convert UUID to [16]byte
	var userID [16]byte
	copy(userID[:], userUUID.Bytes())
	
	// Generate nonce
	var nonce [16]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, newError("failed to generate nonce").Base(err)
	}
	
	// Create client handshake
	clientHandshake := &reflex.ClientHandshake{
		PublicKey: clientPublicKey,
		UserID:    userID,
		PolicyReq: []byte(h.config.Policy),
		Timestamp: time.Now().Unix(),
		Nonce:     nonce,
	}
	
	// Send client handshake
	if err := clientHandshake.Write(conn); err != nil {
		return nil, newError("failed to write client handshake").Base(err)
	}
	
	// Read server handshake
	serverHandshake, err := reflex.ReadServerHandshake(conn)
	if err != nil {
		return nil, newError("failed to read server handshake").Base(err)
	}
	
	// Derive shared key
	sharedKey := reflex.DeriveSharedKey(&clientPrivateKey, &serverHandshake.PublicKey)
	
	// Derive session key
	salt := nonce[:]
	sessionKey := reflex.DeriveSessionKey(sharedKey, salt)
	
	// Create session
	sess, err := reflex.NewSession(sessionKey)
	if err != nil {
		return nil, newError("failed to create session").Base(err)
	}
	
	return sess, nil
}

// relayClientToServer relays data from client to server
func (h *Handler) relayClientToServer(ctx context.Context, sess *reflex.Session, reader buf.Reader, writer io.Writer, destination net.Destination) error {
	// Send destination in first frame (simplified - could be part of handshake)
	// For now, just start relaying data
	
	for {
		mb, err := reader.ReadMultiBuffer()
		if err != nil {
			return err
		}
		
		for _, b := range mb {
			data := b.Bytes()
			
			// Apply traffic morphing
			if h.profile != nil {
				targetSize := h.profile.GetPacketSize()
				delay := h.profile.GetDelay()
				
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
				// No morphing
				if err := sess.WriteFrame(writer, reflex.FrameTypeData, data); err != nil {
					return err
				}
			}
		}
		buf.ReleaseMulti(mb)
	}
}

// relayServerToClient relays data from server to client
func (h *Handler) relayServerToClient(ctx context.Context, sess *reflex.Session, reader io.Reader, writer buf.Writer) error {
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

func init() {
	common.Must(common.RegisterConfig((*reflex.OutboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*reflex.OutboundConfig))
	}))
}
