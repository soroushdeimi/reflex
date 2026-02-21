package outbound

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"io"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	sessionpkg "github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

// Handler implements proxy.Outbound interface for Reflex protocol.
// It handles outbound connections to Reflex servers.
type Handler struct {
	address string
	port    uint32
	id      string // Client UUID
}

// Process handles outbound connections and performs handshake
func (h *Handler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	// Dial server
	dest := net.TCPDestination(net.ParseAddress(h.address), net.Port(h.port))
	conn, err := dialer.Dial(ctx, dest)
	if err != nil {
		return errors.New("failed to dial server").Base(err)
	}
	defer conn.Close()

	// Perform handshake
	sessionKey, err := h.performHandshake(conn)
	if err != nil {
		return errors.New("handshake failed").Base(err)
	}

	log.Record(&log.GeneralMessage{
		Severity: log.Severity_Info,
		Content:  "Reflex: Handshake completed successfully",
	})

	// Create encryption session
	session, err := reflex.NewSession(sessionKey)
	if err != nil {
		return errors.New("failed to create session").Base(err)
	}

	// Process encrypted frames
	return h.handleSession(ctx, conn, link, session)
}

// handleSession processes encrypted frames after handshake
func (h *Handler) handleSession(ctx context.Context, conn io.ReadWriteCloser, link *transport.Link, session *reflex.Session) error {
	reader := bufio.NewReader(conn)

	// Forward data from upstream to server
	go func() {
		var destAddr string
		var destPort net.Port
		firstFrame := true

		for {
			mb, err := link.Reader.ReadMultiBuffer()
			if err != nil {
				// Send close frame and exit
				session.WriteFrame(conn, reflex.FrameTypeClose, nil)
				return
			}

			for _, b := range mb {
				data := b.Bytes()
				if len(data) == 0 {
					b.Release()
					continue
				}

				// Extract destination from session context on first frame
				if firstFrame {
					outbounds := sessionpkg.OutboundsFromContext(ctx)
					if len(outbounds) > 0 {
						dest := outbounds[len(outbounds)-1].Target
						if dest.IsValid() {
							if dest.Address.Family().IsDomain() {
								destAddr = dest.Address.Domain()
							} else {
								destAddr = dest.Address.IP().String()
							}
							destPort = dest.Port
						} else {
							destAddr = "127.0.0.1"
							destPort = 80
						}
					} else {
						destAddr = "127.0.0.1"
						destPort = 80
					}
					firstFrame = false
				}

				// Format payload: [addrLen][address][port][data]
				addrBytes := []byte(destAddr)
				payload := make([]byte, 1+len(addrBytes)+2+len(data))
				payload[0] = byte(len(addrBytes))
				copy(payload[1:], addrBytes)
				binary.BigEndian.PutUint16(payload[1+len(addrBytes):], uint16(destPort))
				copy(payload[1+len(addrBytes)+2:], data)

				if err := session.WriteFrame(conn, reflex.FrameTypeData, payload); err != nil {
					b.Release()
					return
				}
				b.Release()
			}
		}
	}()

	// Forward data from server to upstream
	for {
		frame, err := session.ReadFrame(reader)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return errors.New("failed to read frame").Base(err)
		}

		switch frame.Type {
		case reflex.FrameTypeData:
			// Forward decrypted data to upstream
			buffer := buf.FromBytes(frame.Payload)
			if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{buffer}); err != nil {
				return err
			}

		case reflex.FrameTypePadding:
			// Padding control - ignore
			continue

		case reflex.FrameTypeTiming:
			// Timing control - ignore
			continue

		case reflex.FrameTypeClose:
			// Close connection
			return nil

		default:
			return errors.New("unknown frame type")
		}
	}
}

// performHandshake performs client-side handshake with server
func (h *Handler) performHandshake(conn io.ReadWriteCloser) ([]byte, error) {
	// Get shared secret
	secret, err := reflex.GetSharedSecret(h.id)
	if err != nil {
		return nil, errors.New("failed to get shared secret").Base(err)
	}

	// Convert UUID to bytes
	userID, err := reflex.UserIDToBytes(h.id)
	if err != nil {
		return nil, errors.New("invalid UUID format").Base(err)
	}

	// Generate client key pair
	clientPrivateKey, clientPublicKey, err := reflex.GenerateKeyPair()
	if err != nil {
		return nil, errors.New("failed to generate key pair").Base(err)
	}

	// Generate nonce
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, errors.New("failed to generate nonce").Base(err)
	}

	// Create client handshake
	timestamp := time.Now().Unix()
	clientHS := &reflex.ClientHandshake{
		Version:   reflex.HandshakeVersion,
		PublicKey: clientPublicKey,
		UserID:    userID,
		Timestamp: timestamp,
		Nonce:     nonce,
	}

	// Compute HMAC
	clientHS.HMAC = reflex.ComputeClientHMAC(
		secret,
		clientHS.Version,
		clientHS.PublicKey,
		clientHS.UserID,
		clientHS.Timestamp,
		clientHS.Nonce,
	)

	// Encode and send handshake
	handshakeData := reflex.EncodeClientHandshake(clientHS)
	if _, err := conn.Write(handshakeData); err != nil {
		return nil, errors.New("failed to send handshake").Base(err)
	}

	// Read server response
	serverResponse := make([]byte, 65) // version + pubkey + hmac
	if _, err := io.ReadFull(conn, serverResponse); err != nil {
		return nil, errors.New("failed to read server handshake").Base(err)
	}

	// Decode server handshake
	serverHS, err := reflex.DecodeServerHandshake(serverResponse)
	if err != nil {
		return nil, errors.New("invalid server handshake").Base(err)
	}

	// Verify server HMAC
	expectedServerHMAC := reflex.ComputeServerHMAC(secret, serverHS.Version, serverHS.PublicKey)
	if !hmac.Equal(serverHS.HMAC[:], expectedServerHMAC[:]) {
		return nil, errors.New("server authentication failed")
	}

	// Derive shared secret
	sharedKey := reflex.DeriveSharedKey(clientPrivateKey, serverHS.PublicKey)

	// Derive session key
	sessionKey := reflex.DeriveSessionKey(sharedKey, []byte("reflex-session"))

	return sessionKey, nil
}

// init registers the Reflex outbound handler with Xray-Core.
// This is called automatically when the package is imported.
func init() {
	common.Must(common.RegisterConfig((*reflex.OutboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*reflex.OutboundConfig))
	}))
}

// New creates a new Reflex outbound handler from configuration.
// It parses the config and sets up connection parameters.
func New(ctx context.Context, config *reflex.OutboundConfig) (proxy.Outbound, error) {
	handler := &Handler{
		address: config.Address,
		port:    config.Port,
		id:      config.Id,
	}

	log.Record(&log.GeneralMessage{
		Severity: log.Severity_Info,
		Content:  "Reflex: Outbound handler initialized",
	})

	return handler, nil
}
