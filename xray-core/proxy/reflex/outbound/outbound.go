package outbound

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"time"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	core_session "github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const ReflexMagic = 0x5246584C // "RFXL"

func init() {
	common.Must(common.RegisterConfig((*reflex.OutboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*reflex.OutboundConfig))
	}))
}

type Handler struct {
	config *reflex.OutboundConfig
}

func New(ctx context.Context, config *reflex.OutboundConfig) (proxy.Outbound, error) {
	if config == nil {
		return nil, newError("config is nil")
	}
	return &Handler{config: config}, nil
}

func (h *Handler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	// 1. Extract the destination target from the context
	outbounds := core_session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 {
		return newError("target not specified")
	}
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return newError("invalid target")
	}
	dest := ob.Target

	// 2. Connect to the Reflex server
	serverDest := net.TCPDestination(net.ParseAddress(h.config.Address), net.Port(h.config.Port))
	conn, err := dialer.Dial(ctx, serverDest)
	if err != nil {
		return newError("failed to connect to server").Base(err)
	}
	defer func() { _ = conn.Close() }()

	// 3. Perform the Handshake
	session, err := h.performHandshake(conn)
	if err != nil {
		return newError("handshake failed").Base(err)
	}

	// 4. Prepare initial payload
	var firstPayload []byte
	mb, err := link.Reader.ReadMultiBuffer()
	if err == nil && !mb.IsEmpty() {
		for _, b := range mb {
			if b != nil {
				firstPayload = append(firstPayload, b.Bytes()...)
			}
		}
		buf.ReleaseMulti(mb)
	}

	encodedDest := encodeDest(dest) 
	firstFrameData := append(encodedDest, firstPayload...)

	// 5. Initialize the Dynamic Morpher (Step 5 requirement)
	morpher := reflex.NewDynamicMorpher(30 * time.Second)

	// 6. Write the first morphed frame
	if err := session.WriteFrameWithDynamicMorphing(conn, reflex.FrameTypeData, firstFrameData, morpher); err != nil {
		return newError("failed to write first frame").Base(err)
	}

	// 7. Bidirectional Forwarding with Morphing
	errChan := make(chan error, 2)
	go func() { errChan <- h.pipeUplink(session, conn, link.Reader, morpher) }()
	go func() { errChan <- h.pipeDownlink(session, conn, link.Writer, morpher) }()

	return <-errChan
}

func (h *Handler) performHandshake(conn net.Conn) (*reflex.Session, error) {
	clientPriv, clientPub, err := generateKeyPair()
	if err != nil {
		return nil, err
	}

	// Handshake Packet: [Magic(4)] [PubKey(32)] [UUID(16)] [Time(8)] [Nonce(16)]
	req := make([]byte, 0, 76)
	
	magicBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(magicBuf, ReflexMagic)
	req = append(req, magicBuf...)
	req = append(req, clientPub[:]...)

	uid, err := uuid.Parse(h.config.Id)
	if err != nil {
		return nil, newError("invalid user ID").Base(err)
	}
	uidBytes, _ := uid.MarshalBinary()
	req = append(req, uidBytes...)

	timeBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(timeBuf, uint64(time.Now().Unix()))
	req = append(req, timeBuf...)

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	req = append(req, nonce...)

	if _, err := conn.Write(req); err != nil {
		return nil, err
	}

	// Read Server Public Key
	var serverPub [32]byte
	if _, err := io.ReadFull(conn, serverPub[:]); err != nil {
		return nil, newError("failed to read server response").Base(err)
	}

	sharedKey, err := deriveSharedKey(clientPriv, serverPub)
	if err != nil {
		return nil, err
	}

	// Derive the final session key using HKDF
	sessionKey, err := deriveSessionKey(sharedKey, nonce, []byte("reflex-session-v1"))
	if err != nil {
		return nil, err
	}

	// Correctly handle the two return values from NewSession
	sess, err := reflex.NewSession(sessionKey)
	if err != nil {
		return nil, err
	}
	return sess, nil
}

func (h *Handler) pipeUplink(sess *reflex.Session, conn io.Writer, reader buf.Reader, morpher *reflex.DynamicMorpher) error {
	for {
		mb, err := reader.ReadMultiBuffer()
		if err != nil {
			return err
		}
		for _, b := range mb {
			if b == nil { continue }
			// Apply Advanced Traffic Morphing to outgoing data
			if err := sess.WriteFrameWithDynamicMorphing(conn, reflex.FrameTypeData, b.Bytes(), morpher); err != nil {
				buf.ReleaseMulti(mb) // Ensure memory is released on error
				return err
			}
		}
		buf.ReleaseMulti(mb)
	}
}

func (h *Handler) pipeDownlink(sess *reflex.Session, conn io.Reader, writer buf.Writer, morpher *reflex.DynamicMorpher) error {
	for {
		frame, err := sess.ReadFrame(conn)
		if err != nil {
			return err
		}
		
		switch frame.Type {
		case reflex.FrameTypeData:
			_ = writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(frame.Payload)})
		case reflex.FrameTypePadding, reflex.FrameTypeTiming:
			// Sync shaping from server control frames
			sess.HandleControlFrame(frame, morpher.GetCurrentProfile())
		case reflex.FrameTypeClose:
			return nil
		}
	}
}

// --- Helper Functions ---

func generateKeyPair() ([32]byte, [32]byte, error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return priv, priv, err
	}
	pub, _ := curve25519.X25519(priv[:], curve25519.Basepoint)
	var pub32 [32]byte
	copy(pub32[:], pub)
	return priv, pub32, nil
}

func deriveSharedKey(priv [32]byte, peerPub [32]byte) ([32]byte, error) {
	shared, err := curve25519.X25519(priv[:], peerPub[:])
	var res [32]byte
	copy(res[:], shared)
	return res, err
}

func deriveSessionKey(sharedKey [32]byte, salt []byte, info []byte) ([]byte, error) {
	kdf := hkdf.New(sha256.New, sharedKey[:], salt, info)
	sessionKey := make([]byte, 32)
	if _, err := io.ReadFull(kdf, sessionKey); err != nil {
		return nil, err
	}
	return sessionKey, nil
}

func newError(values ...interface{}) *errors.Error {
	return errors.New(values...)
}

func encodeDest(dest net.Destination) []byte {
	var b []byte
	addr := dest.Address

	switch {
	case addr.Family().IsIPv4():
		b = append(b, 1) // Type 1: IPv4
		b = append(b, addr.IP()...)
	case addr.Family().IsIPv6():
		b = append(b, 3) // Type 3: IPv6
		b = append(b, addr.IP()...)
	case addr.Family().IsDomain():
		b = append(b, 2) // Type 2: Domain
		domain := addr.Domain()
		b = append(b, byte(len(domain)))
		b = append(b, []byte(domain)...)
	}

	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, uint16(dest.Port))
	b = append(b, portBuf...)

	return b
}