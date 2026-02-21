package reflex

import (
	"bufio"
	"context"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	mathrand "math/rand"
	stdnet "net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/stat"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// =========================================================
//
//	Ø«Ø§Ø¨Øªâ€ŒÙ‡Ø§ Ùˆ Ø³Ø§Ø®ØªØ§Ø±Ù‡Ø§ÛŒ Ù¾Ø§ÛŒÙ‡ Reflex
//
// =========================================================
type Handler struct {
	config *InboundConfigntclients interface{}ntfallback interface{}
}

func NewHandler(config *InboundConfigntclients interface{}ntfallback interface{}) *Handler {
	return &Handler{
		config: config,
	}
}

const (
	ReflexMagic            uint32 = 0x5246584C // "REFX"
	ReflexMinHandshakeSize        = 64

	FrameTypeData    = 0x01
	FrameTypePadding = 0x02
	FrameTypeTiming  = 0x03
	FrameTypeClose   = 0x04
)

type ClientHandshake struct {
	PublicKey [32]byte
	UserID    [16]byte
	PolicyReq []byte
	Timestamp int64
	Nonce     [16]byte
}

type ClientHandshakePacket struct {
	Magic     [4]byte
	Handshake ClientHandshake
}

type ServerHandshake struct {
	PublicKey   [32]byte
	PolicyGrant []byte
}

// =========================================================
//                Traffic Morphing Profile
// =========================================================

type PacketSizeDist struct {
	Size   int
	Weight float64
}

type DelayDist struct {
	Delay  time.Duration
	Weight float64
}

type TrafficProfile struct {
	Name           string
	PacketSizes    []PacketSizeDist
	Delays         []DelayDist
	nextPacketSize int
	nextDelay      time.Duration
	mu             sync.Mutex
}

var YouTubeProfile = TrafficProfile{
	Name: "YouTube",
	PacketSizes: []PacketSizeDist{
		{Size: 1400, Weight: 0.35},
		{Size: 1200, Weight: 0.25},
		{Size: 1000, Weight: 0.20},
		{Size: 800, Weight: 0.10},
		{Size: 600, Weight: 0.05},
		{Size: 400, Weight: 0.05},
	},
	Delays: []DelayDist{
		{Delay: 8 * time.Millisecond, Weight: 0.30},
		{Delay: 12 * time.Millisecond, Weight: 0.25},
		{Delay: 16 * time.Millisecond, Weight: 0.20},
		{Delay: 20 * time.Millisecond, Weight: 0.15},
		{Delay: 30 * time.Millisecond, Weight: 0.10},
	},
}

func (p *TrafficProfile) GetPacketSize() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.nextPacketSize > 0 {
		size := p.nextPacketSize
		p.nextPacketSize = 0
		return size
	}

	r := mathrand.Float64()
	cumsum := 0.0
	for _, dist := range p.PacketSizes {
		cumsum += dist.Weight
		if r <= cumsum {
			return dist.Size
		}
	}
	return p.PacketSizes[len(p.PacketSizes)-1].Size
}

func (p *TrafficProfile) GetDelay() time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.nextDelay > 0 {
		delay := p.nextDelay
		p.nextDelay = 0
		return delay
	}

	r := mathrand.Float64()
	cumsum := 0.0
	for _, dist := range p.Delays {
		cumsum += dist.Weight
		if r <= cumsum {
			return dist.Delay
		}
	}
	return p.Delays[len(p.Delays)-1].Delay
}

func (p *TrafficProfile) SetNextPacketSize(size int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.nextPacketSize = size
}

func (p *TrafficProfile) SetNextDelay(delay time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.nextDelay = delay
}

func calculateSizeDistribution(values []int) []PacketSizeDist {
	freq := make(map[int]int)
	for _, v := range values {
		freq[v]++
	}
	total := len(values)
	dist := make([]PacketSizeDist, 0, len(freq))
	for size, count := range freq {
		dist = append(dist, PacketSizeDist{
			Size:   size,
			Weight: float64(count) / float64(total),
		})
	}
	sort.Slice(dist, func(i, j int) bool {
		return dist[i].Size < dist[j].Size
	})
	return dist
}

func calculateDelayDistribution(values []time.Duration) []DelayDist {
	freq := make(map[time.Duration]int)
	for _, v := range values {
		freq[v]++
	}
	total := len(values)
	dist := make([]DelayDist, 0, len(freq))
	for delay, count := range freq {
		dist = append(dist, DelayDist{
			Delay:  delay,
			Weight: float64(count) / float64(total),
		})
	}
	sort.Slice(dist, func(i, j int) bool {
		return dist[i].Delay < dist[j].Delay
	})
	return dist
}

func CreateProfileFromCapture(packetSizes []int, delays []time.Duration) *TrafficProfile {
	sizeDist := calculateSizeDistribution(packetSizes)
	delayDist := calculateDelayDistribution(delays)
	return &TrafficProfile{
		PacketSizes: sizeDist,
		Delays:      delayDist,
	}
}

// =========================================================
//                ØªÙˆØ§Ø¨Ø¹ Ù¾Ø§ÛŒÙ‡Ù” Ø±Ù…Ø²Ù†Ú¯Ø§Ø±ÛŒ
// =========================================================

func deriveSharedKey(privateKey, peerPublicKey [32]byte) [32]byte {
	var shared [32]byte
	curve25519.ScalarMult(&shared, &privateKey, &peerPublicKey)
	return shared
}

func deriveSessionKey(sharedKey [32]byte, salt []byte) []byte {
	hk := hkdf.New(sha256.New, sharedKey[:], salt, []byte("reflex-session"))
	sessionKey := make([]byte, 32)
	hk.Read(sessionKey)
	return sessionKey
}

// =========================================================
//                Ø§Ø­Ø±Ø§Ø² Ù‡ÙˆÛŒØª Ú©Ø§Ø±Ø¨Ø± Ø¨Ø§ UUID
// =========================================================

func (h *Handler) authenticateUser(userID [16]byte) (*protocol.MemoryUser, error) {
	userIDStr := uuid.UUID(userID).String()
	for _, user := range h.clients {
		if user.Account.(*MemoryAccount).Id == userIDStr {
			return user, nil
		}
	}
	return nil, errors.New("user not found")
}

// =========================================================
//        ØªØ´Ø®ÛŒØµ Reflex vs HTTP vs fallback (Peek)
// =========================================================

func (h *Handler) isReflexMagic(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	magic := binary.BigEndian.Uint32(data[0:4])
	return magic == ReflexMagic
}

func (h *Handler) isHTTPPostLike(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	if string(data[0:4]) != "POST" {
		return false
	}
	return true
}

func (h *Handler) isReflexHandshake(data []byte) bool {
	if h.isReflexMagic(data) {
		return true
	}
	if h.isHTTPPostLike(data) {
		return true
	}
	return false
}

func (h *Handler) Process(ctx context.Context, network xnet.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	reader := bufio.NewReader(conn)

	peeked, err := reader.Peek(ReflexMinHandshakeSize)
	if err != nil && err != io.EOF {
		return err
	}

	if h.isReflexHandshake(peeked) {
		if len(peeked) >= 4 {
			magic := binary.BigEndian.Uint32(peeked[0:4])
			if magic == ReflexMagic {
				return h.handleReflexMagic(ctx, reader, conn, dispatcher)
			}
		}
		if h.isHTTPPostLike(peeked) {
			return h.handleReflexHTTP(ctx, reader, conn, dispatcher)
		}
		return h.handleFallback(ctx, reader, conn)
	}

	return h.handleFallback(ctx, reader, conn)
}

// =========================================================
//        HTTP POST-like Handshake
// =========================================================

func (h *Handler) handleReflexHTTP(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher) error {
	reqBytes, err := io.ReadAll(reader)
	if err != nil {
		return h.handleFallback(ctx, reader, conn)
	}

	req := string(reqBytes)
	idx := strings.Index(req, "{")
	if idx == -1 {
		return h.handleFallback(ctx, reader, conn)
	}

	jsonPart := req[idx:]
	var body struct {
		Data string `json:"data"`
	}
	if err := json.Unmarshal([]byte(jsonPart), &body); err != nil {
		return h.handleFallback(ctx, reader, conn)
	}

	decoded, err := base64.StdEncoding.DecodeString(body.Data)
	if err != nil {
		return h.handleFallback(ctx, reader, conn)
	}
	if len(decoded) < 72 {
		return h.handleFallback(ctx, reader, conn)
	}

	var hs ClientHandshake
	copy(hs.PublicKey[:], decoded[0:32])
	copy(hs.UserID[:], decoded[32:48])
	hs.Timestamp = int64(binary.BigEndian.Uint64(decoded[48:56]))
	copy(hs.Nonce[:], decoded[56:72])

	return h.processHandshake(ctx, reader, conn, dispatcher, hs)
}

// =========================================================
//        Ø­Ø§Ù„Øª Ø¨Ø§ÛŒÙ†Ø±ÛŒ (Magic Number)
// =========================================================

func (h *Handler) handleReflexMagic(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher) error {
	magic := make([]byte, 4)
	if _, err := io.ReadFull(reader, magic); err != nil {
		return err
	}

	var packet ClientHandshakePacket
	copy(packet.Magic[:], magic)

	fixed := make([]byte, 72)
	if _, err := io.ReadFull(reader, fixed); err != nil {
		return err
	}

	copy(packet.Handshake.PublicKey[:], fixed[0:32])
	copy(packet.Handshake.UserID[:], fixed[32:48])
	packet.Handshake.Timestamp = int64(binary.BigEndian.Uint64(fixed[48:56]))
	copy(packet.Handshake.Nonce[:], fixed[56:72])

	return h.processHandshake(ctx, reader, conn, dispatcher, packet.Handshake)
}

// =========================================================
//        Fallback ÙˆØ§Ù‚Ø¹ÛŒ Ø¨Ù‡ ÙˆØ¨â€ŒØ³Ø±ÙˆØ±
// =========================================================

type preloadedConn struct {
	*bufio.Reader
	stat.Connection
}

func (pc *preloadedConn) Read(b []byte) (int, error) {
	return pc.Reader.Read(b)
}

func (pc *preloadedConn) Write(b []byte) (int, error) {
	return pc.Connection.Write(b)
}

func (h *Handler) handleFallback(ctx context.Context, reader *bufio.Reader, conn stat.Connection) error {
	if h.fallback == nil {
		return errors.New("no fallback configured")
	}

	wrappedConn := &preloadedConn{
		Reader:     reader,
		Connection: conn,
	}

	target, err := stdnet.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", h.fallback.Dest))
	if err != nil {
		return err
	}
	defer target.Close()

	go io.Copy(target, wrappedConn)
	io.Copy(wrappedConn, target)

	return nil
}

// =========================================================
//        Frame Ùˆ Session Ùˆ Replay Protection
// =========================================================

type Frame struct {
	Length  uint16
	Type    uint8
	Payload []byte
}

type NonceCache struct {
	seen map[uint64]bool
	mu   sync.Mutex
}

func NewNonceCache() *NonceCache {
	return &NonceCache{
		seen: make(map[uint64]bool),
	}
}

func (nc *NonceCache) Check(nonce uint64) bool {
	nc.mu.Lock()
	defer nc.mu.Unlock()

	if nc.seen[nonce] {
		return false
	}
	nc.seen[nonce] = true
	if len(nc.seen) > 1000 {
		nc.seen = make(map[uint64]bool)
	}
	return true
}

type Session struct {
	key             []byte
	aead            cipher.AEAD
	readNonce       uint64
	writeNonce      uint64
	nonceCache      *NonceCache
	profile         *TrafficProfile
	morphingEnabled bool
}

func NewSession(sessionKey []byte) (*Session, error) {
	aead, err := chacha20poly1305.New(sessionKey)
	if err != nil {
		return nil, err
	}
	return &Session{
		key:             sessionKey,
		aead:            aead,
		readNonce:       0,
		writeNonce:      0,
		nonceCache:      NewNonceCache(),
		profile:         &YouTubeProfile,
		morphingEnabled: true,
	}, nil
}

func (s *Session) StartYouTubeMorphing() {
	s.profile = &YouTubeProfile
	s.morphingEnabled = true
}

func (s *Session) ReadFrame(reader io.Reader) (*Frame, error) {
	header := make([]byte, 3)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint16(header[0:2])
	frameType := header[2]

	encryptedPayload := make([]byte, length)
	if _, err := io.ReadFull(reader, encryptedPayload); err != nil {
		return nil, err
	}

	if !s.nonceCache.Check(s.readNonce) {
		return nil, errors.New("replay detected")
	}

	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], s.readNonce)
	s.readNonce++

	payload, err := s.aead.Open(nil, nonce, encryptedPayload, nil)
	if err != nil {
		return nil, err
	}

	return &Frame{
		Length:  length,
		Type:    frameType,
		Payload: payload,
	}, nil
}

func (s *Session) WriteFrame(writer io.Writer, frameType uint8, data []byte) error {
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], s.writeNonce)
	s.writeNonce++

	encrypted := s.aead.Seal(nil, nonce, data, nil)

	header := make([]byte, 3)
	binary.BigEndian.PutUint16(header[0:2], uint16(len(encrypted)))
	header[2] = frameType

	if _, err := writer.Write(header); err != nil {
		return err
	}
	if _, err := writer.Write(encrypted); err != nil {
		return err
	}
	return nil
}

func (s *Session) AddPadding(data []byte, targetSize int) []byte {
	if len(data) >= targetSize {
		return data[:targetSize]
	}
	padding := make([]byte, targetSize-len(data))
	mathrand.Read(padding)
	return append(data, padding...)
}

func (s *Session) WriteFrameWithMorphing(writer io.Writer, frameType uint8, data []byte, profile *TrafficProfile) error {
	targetSize := profile.GetPacketSize()

	if len(data) > targetSize {
		firstChunk := data[:targetSize]
		if err := s.writeFrameChunk(writer, frameType, firstChunk, profile); err != nil {
			return err
		}
		remaining := data[targetSize:]
		return s.WriteFrameWithMorphing(writer, frameType, remaining, profile)
	}

	morphedData := s.AddPadding(data, targetSize)

	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], s.writeNonce)
	s.writeNonce++

	encrypted := s.aead.Seal(nil, nonce, morphedData, nil)

	header := make([]byte, 3)
	binary.BigEndian.PutUint16(header[0:2], uint16(len(encrypted)))
	header[2] = frameType

	_, _ = writer.Write(header)
	_, _ = writer.Write(encrypted)

	delay := profile.GetDelay()
	time.Sleep(delay)

	return nil
}

func (s *Session) writeFrameChunk(writer io.Writer, frameType uint8, data []byte, profile *TrafficProfile) error {
	return s.WriteFrameWithMorphing(writer, frameType, data, profile)
}

func (s *Session) SendPaddingControl(writer io.Writer, targetSize int) error {
	ctrlData := make([]byte, 2)
	binary.BigEndian.PutUint16(ctrlData, uint16(targetSize))
	return s.WriteFrame(writer, FrameTypePadding, ctrlData)
}

func (s *Session) SendTimingControl(writer io.Writer, delay time.Duration) error {
	ctrlData := make([]byte, 8)
	binary.BigEndian.PutUint64(ctrlData, uint64(delay.Milliseconds()))
	return s.WriteFrame(writer, FrameTypeTiming, ctrlData)
}

func (s *Session) HandleControlFrame(frame *Frame, profile *TrafficProfile) {
	switch frame.Type {
	case FrameTypePadding:
		if len(frame.Payload) >= 2 {
			targetSize := int(binary.BigEndian.Uint16(frame.Payload))
			profile.SetNextPacketSize(targetSize)
		}
	case FrameTypeTiming:
		if len(frame.Payload) >= 8 {
			delayMs := binary.BigEndian.Uint64(frame.Payload)
			profile.SetNextDelay(time.Duration(delayMs) * time.Millisecond)
		}
	}
}

// =========================================================
//        Handshake + Ø´Ø±ÙˆØ¹ Session (Frame-based + Morphing)
// =========================================================

func (h *Handler) processHandshake(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, clientHS ClientHandshake) error {
	var serverPriv, serverPub [32]byte
	curve25519.ScalarBaseMult(&serverPub, &serverPriv)

	sharedKey := deriveSharedKey(serverPriv, clientHS.PublicKey)
	sessionKey := deriveSessionKey(sharedKey, []byte("reflex-session"))

	user, err := h.authenticateUser(clientHS.UserID)
	if err != nil {
		return h.handleFallback(ctx, reader, conn)
	}

	respObj := map[string]string{
		"status": "ok",
	}
	respJSON, _ := json.Marshal(respObj)
	response := []byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + string(respJSON))
	if _, err := conn.Write(response); err != nil {
		return err
	}

	return h.handleSession(ctx, reader, conn, dispatcher, sessionKey, user)
}

// =========================================================
//        Session: Ù¾Ø±Ø¯Ø§Ø²Ø´ FrameÙ‡Ø§ Ùˆ Ø¯Ø§Ø¯Ù‡â€ŒÙ‡Ø§
// =========================================================

func (h *Handler) handleSession(
	ctx context.Context,
	reader *bufio.Reader,
	conn stat.Connection,
	dispatcher routing.Dispatcher,
	sessionKey []byte,
	user *protocol.MemoryUser,
) error {
	session, err := NewSession(sessionKey)
	if err != nil {
		return err
	}
	session.StartYouTubeMorphing()

	for {
		frame, err := session.ReadFrame(reader)
		if err != nil {
			return err
		}

		switch frame.Type {
		case FrameTypeData:
			if err := h.handleData(ctx, frame.Payload, conn, dispatcher, session, user); err != nil {
				return err
			}
		case FrameTypePadding, FrameTypeTiming:
			if session.profile != nil {
				session.HandleControlFrame(frame, session.profile)
			}
		case FrameTypeClose:
			return nil
		default:
			return errors.New("unknown frame type")
		}
	}
}

// =========================================================
//        Ù¾Ø±Ø¯Ø§Ø²Ø´ Ø¯Ø§Ø¯Ù‡â€ŒÙ‡Ø§ÛŒ ÙˆØ§Ù‚Ø¹ÛŒ (Data Frames)
// =========================================================

func (h *Handler) handleData(
	ctx context.Context,
	data []byte,
	conn stat.Connection,
	dispatcher routing.Dispatcher,
	session *Session,
	user *protocol.MemoryUser,
) error {
	// TODO: Ø¯Ø± Ù†Ø³Ø®Ù‡Ù” ÙˆØ§Ù‚Ø¹ÛŒØŒ dest Ø§Ø² data Ø§Ø³ØªØ®Ø±Ø§Ø¬ Ù…ÛŒâ€ŒØ´ÙˆØ¯
	dest := xnet.TCPDestination(xnet.ParseAddress("example.com"), xnet.Port(80))

	link, err := dispatcher.Dispatch(ctx, dest)
	if err != nil {
		return err
	}

	buffer := buf.FromBytes(data)
	if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{buffer}); err != nil {
		return err
	}

	go func() {
		defer link.Writer.Close()
		for {
			mb, err := link.Reader.ReadMultiBuffer()
			if err != nil {
				return
			}
			for _, b := range mb {
				if session.morphingEnabled && session.profile != nil {
					_ = session.WriteFrameWithMorphing(conn, FrameTypeData, b.Bytes(), session.profile)
				} else {
					_ = session.WriteFrame(conn, FrameTypeData, b.Bytes())
				}
				b.Release()
			}
		}
	}()

	return nil
}
