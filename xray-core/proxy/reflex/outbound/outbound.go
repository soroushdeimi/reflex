package outbound

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

// Handler is an outbound handler for Reflex protocol.
type Handler struct {
	address         string
	port            uint32
	id              string
	morphingEnabled bool
}

// New creates a new Reflex outbound handler from the generated OutboundConfig.
func New(ctx context.Context, config *reflex.OutboundConfig) (*Handler, error) {
	_ = ctx
	return &Handler{
		address:         config.Address,
		port:            config.Port,
		id:              config.Id,
		morphingEnabled: config.GetMorphingEnabled(),
	}, nil
}

// Process implements proxy.Outbound.Process.
func (h *Handler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	// Get target destination from context
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 {
		return errors.New("reflex: no outbound target")
	}
	target := outbounds[len(outbounds)-1].Target
	if !target.IsValid() {
		return errors.New("reflex: invalid target")
	}

	// Parse client UUID
	clientUUID, err := uuid.Parse(h.id)
	if err != nil {
		return fmt.Errorf("reflex: invalid client UUID: %w", err)
	}

	// Dial server
	dest := xnet.TCPDestination(xnet.ParseAddress(h.address), xnet.Port(h.port))
	conn, err := dialer.Dial(ctx, dest)
	if err != nil {
		return fmt.Errorf("reflex: failed to dial server: %w", err)
	}
	defer conn.Close()

	// Perform handshake and get the reader for frame reading
	reader, session, err := h.performHandshake(conn, clientUUID)
	if err != nil {
		return fmt.Errorf("reflex: handshake failed: %w", err)
	}

	// Handle bidirectional data flow
	return h.handleSession(ctx, conn, reader, link, session, target)
}

// performHandshake performs the Reflex handshake: sends ClientHandshakePacket,
// receives HTTP response with server public key, and derives session key.
// Returns the reader (which may have buffered data) and the session.
func (h *Handler) performHandshake(conn net.Conn, clientUUID uuid.UUID) (*bufio.Reader, *reflex.Session, error) {
	// Generate client key pair
	clientPriv, clientPub, err := reflex.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}

	// Build handshake packet
	packet := &reflex.ClientHandshakePacket{
		Magic: reflex.ReflexMagic,
		Handshake: reflex.ClientHandshake{
			PublicKey: clientPub,
			UserID:    [16]byte(clientUUID),
			PolicyReq: nil,
			Timestamp: time.Now().Unix(),
			Nonce:     [16]byte{},
		},
	}

	// Generate random nonce
	if _, err := io.ReadFull(rand.Reader, packet.Handshake.Nonce[:]); err != nil {
		return nil, nil, err
	}

	// Encode and send handshake
	handshakeBytes := reflex.EncodeClientHandshakePacket(packet)
	if _, err := conn.Write(handshakeBytes); err != nil {
		return nil, nil, err
	}

	// Read HTTP response - create reader once and reuse it
	reader := bufio.NewReader(conn)

	// Read status line
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		return nil, nil, err
	}
	if !strings.HasPrefix(statusLine, "HTTP/1.1 200") {
		return nil, nil, fmt.Errorf("reflex: server returned non-200 status: %s", strings.TrimSpace(statusLine))
	}

	// Read headers until empty line
	var contentLength int
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, nil, err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}
		if strings.HasPrefix(strings.ToLower(line), "content-length:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				if n, err := strconv.Atoi(strings.TrimSpace(parts[1])); err == nil {
					contentLength = n
				}
			}
		}
	}

	// Read body
	body := make([]byte, contentLength)
	if contentLength > 0 {
		if _, err := io.ReadFull(reader, body); err != nil {
			return nil, nil, err
		}
	}

	var response struct {
		Status    string `json:"status"`
		PublicKey string `json:"publicKey"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, nil, err
	}

	serverPubB, err := base64.StdEncoding.DecodeString(response.PublicKey)
	if err != nil || len(serverPubB) != 32 {
		return nil, nil, errors.New("reflex: invalid server public key")
	}

	var serverPub [32]byte
	copy(serverPub[:], serverPubB)

	// Derive session key
	shared := reflex.DeriveSharedKey(clientPriv, serverPub)
	sessionKey := reflex.DeriveSessionKey(shared, []byte("reflex-session"))
	if sessionKey == nil {
		return nil, nil, errors.New("reflex: failed to derive session key")
	}

	// Create session
	sess, err := reflex.NewSession(sessionKey)
	if err != nil {
		return nil, nil, err
	}

	// Return the reader (which may have buffered data) and the session
	return reader, sess, nil
}

// encodeDestination encodes the destination address and port into the format
// expected by the Reflex protocol: [1 byte type][address bytes][2 bytes port BE]
func encodeDestination(dest xnet.Destination) ([]byte, error) {
	var data []byte
	var addrType byte

	switch dest.Address.Family() {
	case xnet.AddressFamilyDomain:
		addrType = 0
		domain := dest.Address.Domain()
		if len(domain) > 255 {
			return nil, errors.New("reflex: domain too long")
		}
		data = append(data, addrType)
		data = append(data, byte(len(domain)))
		data = append(data, []byte(domain)...)
	case xnet.AddressFamilyIPv4:
		addrType = 1
		data = append(data, addrType)
		data = append(data, dest.Address.IP()...)
	case xnet.AddressFamilyIPv6:
		addrType = 2
		data = append(data, addrType)
		data = append(data, dest.Address.IP()...)
	default:
		return nil, errors.New("reflex: unsupported address family")
	}

	// Append port (big-endian)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(dest.Port))
	data = append(data, portBytes...)

	return data, nil
}

// handleSession handles the encrypted session: reads from link, sends DATA frames
// (with morphing if enabled), reads frames from server (stripping morphing prefix if enabled), and writes to link.
func (h *Handler) handleSession(ctx context.Context, conn net.Conn, reader *bufio.Reader, link *transport.Link, sess *reflex.Session, target xnet.Destination) error {
	firstData := true

	// Per-connection traffic profile for morphing (only if enabled).
	var profile *reflex.TrafficProfile
	if h.morphingEnabled {
		profile = &reflex.TrafficProfile{
			Name:        reflex.HTTP2APIProfile.Name,
			PacketSizes: reflex.HTTP2APIProfile.PacketSizes,
			Delays:      reflex.HTTP2APIProfile.Delays,
		}
	}

	// Goroutine: read from link, encode and send as DATA frames (with morphing if enabled)
	go func() {
		defer func() {
			// Send CLOSE frame to server when done reading from upstream
			_ = sess.WriteFrame(conn, reflex.FrameTypeClose, nil)
			common.Close(link.Writer)
		}()
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			mb, err := link.Reader.ReadMultiBuffer()
			if err != nil {
				// EOF or closed pipe is expected when upstream closes
				return
			}
			for _, b := range mb {
				payload := b.Bytes()
				b.Release()

				var framePayload []byte
				if firstData {
					// First DATA frame: encode destination + payload
					destBytes, err := encodeDestination(target)
					if err != nil {
						return
					}
					framePayload = append(destBytes, payload...)
					firstData = false
				} else {
					framePayload = payload
				}

				if profile != nil {
					if err := sess.WriteFrameWithMorphing(conn, reflex.FrameTypeData, framePayload, profile); err != nil {
						return
					}
				} else {
					if err := sess.WriteFrame(conn, reflex.FrameTypeData, framePayload); err != nil {
						return
					}
				}
			}
		}
	}()

	// Main loop: read frames from server, write decrypted payloads to link
	for {
		frame, err := sess.ReadFrame(reader)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}

		switch frame.Type {
		case reflex.FrameTypeData:
			// Strip traffic morphing prefix if morphing is enabled.
			payload := frame.Payload
			if h.morphingEnabled {
				if stripped, ok := reflex.StripMorphingPrefix(payload); ok {
					payload = stripped
				}
			}
			if len(payload) > 0 {
				b := buf.New()
				if _, err := b.Write(payload); err != nil {
					return err
				}
				if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
					return err
				}
			}
		case reflex.FrameTypeClose:
			return nil
		case reflex.FrameTypePadding, reflex.FrameTypeTiming:
			if profile != nil {
				sess.HandleControlFrame(frame, profile)
			}
		default:
			return fmt.Errorf("reflex: unknown frame type %d", frame.Type)
		}
	}
}

func init() {
	common.Must(common.RegisterConfig((*reflex.OutboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*reflex.OutboundConfig))
	}))
}
