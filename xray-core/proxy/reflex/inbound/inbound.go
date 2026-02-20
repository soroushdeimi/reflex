package inbound

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"io"
	stdnet "net"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport/internet/stat"
)


type Handler struct {
	clients  []*protocol.MemoryUser
	fallback *FallbackConfig
}


type MemoryAccount struct {
	Id     string
	Policy string
}


type FallbackConfig struct {
	Dest uint32
}


type preloadedConn struct {
	*bufio.Reader
	stat.Connection
}

func (c *preloadedConn) Read(p []byte) (int, error) {
	return c.Reader.Read(p)
}

func (c *preloadedConn) Write(p []byte) (int, error) {
	return c.Connection.Write(p)
}

func (a *MemoryAccount) Equals(acc protocol.Account) bool {
	if other, match := acc.(*MemoryAccount); match {
		return a.Id == other.Id
	}
	return false
}

func (a *MemoryAccount) ToProto() proto.Message {
	return &reflex.Account{Id: a.Id}
}

func (h *Handler) Network() []net.Network {
	return []net.Network{net.Network_TCP}
}

func (h *Handler) Process(ctx context.Context, netwk net.Network, connection stat.Connection, router routing.Dispatcher) error {
	ioStream := bufio.NewReader(connection)
	
	headerMagic, err := ioStream.Peek(4)
	if err != nil && err != io.EOF {
		return err
	}

	if len(headerMagic) < 4 {
		return h.routeToFallback(ctx, ioStream, connection)
	}

	switch {
	case binary.BigEndian.Uint32(headerMagic) == ReflexMagic:
		fullHeader, err := ioStream.Peek(MinHandshakeSize)
		if err != nil && err != io.EOF {
			return err
		}
		if len(fullHeader) < MinHandshakeSize {
			return h.routeToFallback(ctx, ioStream, connection)
		}
		return h.processNativeReflex(ctx, ioStream, connection, router)

	case h.isHTTPPostLike(headerMagic):
		return h.processHTTPReflex(ctx, ioStream, connection, router)

	default:
		return h.routeToFallback(ctx, ioStream, connection)
	}
}

func (h *Handler) processNativeReflex(ctx context.Context, stream *bufio.Reader, conn stat.Connection, router routing.Dispatcher) error {
	clientReq, err := readClientHandshakeMagic(stream)
	if err != nil {
		return h.routeToFallback(ctx, stream, conn)
	}
	return h.finalizeConnection(ctx, stream, conn, router, clientReq)
}

func (h *Handler) processHTTPReflex(ctx context.Context, stream *bufio.Reader, conn stat.Connection, router routing.Dispatcher) error {
	clientReq, err := h.extractHTTPHandshake(stream)
	if err != nil {
		return h.routeToFallback(ctx, stream, conn)
	}
	return h.finalizeConnection(ctx, stream, conn, router, clientReq)
}

// extractHTTPHandshake isolates the parsing of HTTP POST requests
func (h *Handler) extractHTTPHandshake(stream *bufio.Reader) (*ClientHandshake, error) {
	reqLine, err := stream.ReadString('\n')
	if err != nil || !strings.HasPrefix(reqLine, "POST") {
		return nil, errors.New("invalid post method")
	}

	var payloadSize int64
	for {
		headerLine, err := stream.ReadString('\n')
		if err != nil || headerLine == "\n" || headerLine == "\r\n" {
			break
		}
		
		lowerHeader := strings.ToLower(headerLine)
		if strings.HasPrefix(lowerHeader, "content-length:") {
			parts := strings.Split(lowerHeader, ":")
			if len(parts) >= 2 {
				sizeStr := strings.TrimSpace(parts[1])
				payloadSize, _ = strconv.ParseInt(sizeStr, 10, 64)
			}
		}
	}

	if payloadSize == 0 || payloadSize > 65536 {
		return nil, errors.New("invalid payload size")
	}

	encodedData := make([]byte, payloadSize)
	if _, err := io.ReadFull(stream, encodedData); err != nil {
		return nil, err
	}

	rawBytes, err := base64.StdEncoding.DecodeString(string(encodedData))
	if err != nil || len(rawBytes) < MinHandshakeSize {
		return nil, errors.New("base64 decode failure or size mismatch")
	}

	decodedStream := bufio.NewReader(bytes.NewReader(rawBytes))
	
	var magicIndicator [4]byte
	if _, err := io.ReadFull(decodedStream, magicIndicator[:]); err != nil {
		return nil, err
	}
	if binary.BigEndian.Uint32(magicIndicator[:]) != ReflexMagic {
		return nil, errors.New("magic mismatch in decoded stream")
	}

	handshakeReq := &ClientHandshake{}
	io.ReadFull(decodedStream, handshakeReq.PublicKey[:])
	io.ReadFull(decodedStream, handshakeReq.UserID[:])
	binary.Read(decodedStream, binary.BigEndian, &handshakeReq.Timestamp)
	io.ReadFull(decodedStream, handshakeReq.Nonce[:])

	return handshakeReq, nil
}

func (h *Handler) finalizeConnection(ctx context.Context, stream *bufio.Reader, conn stat.Connection, router routing.Dispatcher, req *ClientHandshake) error {
	srvPrivKey, srvPubKey, err := generateKeyPair()
	if err != nil {
		return err
	}

	sharedSecret := deriveSharedKey(srvPrivKey, req.PublicKey)
	sessionToken := deriveSessionKey(sharedSecret, []byte("reflex-session"))

	authorizedUser := h.authenticateUser(req.UserID)
	if authorizedUser == nil {
		return h.routeToFallback(ctx, stream, conn)
	}

	srvResponse := &ServerHandshake{
		PublicKey:   srvPubKey,
		PolicyGrant: []byte{},
	}
	
	if err := writeServerHandshakeMagic(conn, srvResponse); err != nil {
		return err
	}

	return h.beginSession(ctx, stream, conn, router, sessionToken, authorizedUser)
}

func (h *Handler) beginSession(ctx context.Context, stream *bufio.Reader, conn stat.Connection, router routing.Dispatcher, key []byte, u *protocol.MemoryUser) error {
	activeSess, err := NewSession(key)
	if err != nil {
		return err
	}
	
	accRef := u.Account.(*MemoryAccount)
	trafficProf := h.getProfile(accRef.Policy)

	initialFrame, err := activeSess.ReadFrame(stream)
	if err != nil {
		return err
	}
	
	if initialFrame.Type != FrameTypeData {
		return errors.New("reflex: expected DATA as initial frame")
	}
	
	return h.relayData(ctx, initialFrame.Payload, stream, conn, router, activeSess, trafficProf)
}

// parseDest isolates the logic for extracting network destinations.
// Returns (destination, bytes consumed, ok). When ok is false, destination is zero and must not be used.
func parseDest(chunk []byte) (net.Destination, int, bool) {
	if len(chunk) < 4 {
		return net.Destination{}, 0, false
	}

	switch chunk[0] {
	case 1: // IPv4
		if len(chunk) >= 7 {
			ip := net.IPAddress(chunk[1:5])
			port := net.Port(binary.BigEndian.Uint16(chunk[5:7]))
			return net.TCPDestination(ip, port), 7, true
		}
	case 2: // Domain
		dLen := int(chunk[1])
		if len(chunk) >= 4+dLen {
			domain := net.DomainAddress(string(chunk[2 : 2+dLen]))
			port := net.Port(binary.BigEndian.Uint16(chunk[2+dLen : 4+dLen]))
			return net.TCPDestination(domain, port), 4 + dLen, true
		}
	case 3: // IPv6
		if len(chunk) >= 19 {
			ip := net.IPAddress(chunk[1:17])
			port := net.Port(binary.BigEndian.Uint16(chunk[17:19]))
			return net.TCPDestination(ip, port), 19, true
		}
	}

	return net.Destination{}, 0, false
}

func (h *Handler) relayData(ctx context.Context, firstChunk []byte, stream *bufio.Reader, conn stat.Connection, router routing.Dispatcher, activeSess *Session, trafficProf *TrafficProfile) error {
	targetDest, dataOffset, ok := parseDest(firstChunk)
	if !ok {
		return nil
	}

	upstream, err := router.Dispatch(ctx, targetDest)
	if err != nil {
		return err
	}

	if dataOffset < len(firstChunk) {
		remainder := buf.FromBytes(firstChunk[dataOffset:])
		if err := upstream.Writer.WriteMultiBuffer(buf.MultiBuffer{remainder}); err != nil {
			return err
		}
	}

	// Downlink Processing
	go func() {
		for {
			packets, err := upstream.Reader.ReadMultiBuffer()
			if err != nil || packets.IsEmpty() {
				return
			}
			
			for _, packet := range packets {
				if packet.Len() > 0 {
					obfuscatedData, delayDur := trafficProf.ApplyMorphing(packet.Bytes())
					_ = activeSess.WriteFrame(conn, FrameTypeData, obfuscatedData)
					
					if delayDur > 0 {
						time.Sleep(delayDur)
					}
				}
				packet.Release()
			}
		}
	}()

	// Uplink Processing
	for {
		frm, err := activeSess.ReadFrame(stream)
		if err != nil {
			return err
		}
		
		switch frm.Type {
		case FrameTypeData:
			if len(frm.Payload) > 0 {
				newBuf := buf.FromBytes(frm.Payload)
				if err := upstream.Writer.WriteMultiBuffer(buf.MultiBuffer{newBuf}); err != nil {
					return err
				}
			}
		case FrameTypePadding, FrameTypeTiming:
			h.handleControlFrame(frm, trafficProf)
		case FrameTypeClose:
			return nil
		default:
			return errors.New("reflex: unrecognized frame type encountered").AtWarning()
		}
	}
}

func (h *Handler) isHTTPPostLike(data []byte) bool {
	return len(data) >= 4 && string(data[:4]) == "POST"
}

// processHandshake runs handshake and session for a client handshake (used by tests).
func (h *Handler) processHandshake(ctx context.Context, r *bufio.Reader, conn stat.Connection, d routing.Dispatcher, hs *ClientHandshake) error {
	return h.finalizeConnection(ctx, r, conn, d, hs)
}

// handleSession runs the session loop after handshake (used by tests).
func (h *Handler) handleSession(ctx context.Context, r *bufio.Reader, conn stat.Connection, router routing.Dispatcher, key []byte, u *protocol.MemoryUser) error {
	return h.beginSession(ctx, r, conn, router, key, u)
}

// handleDataFrame relays the first data chunk and runs relay loop (used by tests).
func (h *Handler) handleDataFrame(ctx context.Context, firstChunk []byte, stream *bufio.Reader, conn stat.Connection, router routing.Dispatcher, sess *Session, _ *protocol.MemoryUser, prof *TrafficProfile) error {
	return h.relayData(ctx, firstChunk, stream, conn, router, sess, prof)
}

func (h *Handler) routeToFallback(ctx context.Context, stream *bufio.Reader, conn stat.Connection) error {
	if h.fallback == nil {
		return errNotReflex
	}

	portStr := strconv.Itoa(int(h.fallback.Dest))
	backendAddress := stdnet.JoinHostPort("127.0.0.1", portStr)
	
	backendDial, err := stdnet.Dial("tcp", backendAddress)
	if err != nil {
		return err
	}
	defer backendDial.Close()

	bridgedConn := &preloadedConn{Reader: stream, Connection: conn}
	
	go io.Copy(backendDial, bridgedConn)
	_, _ = io.Copy(bridgedConn, backendDial)
	
	return nil
}

func init() {
	common.Must(common.RegisterConfig((*reflex.InboundConfig)(nil), func(ctx context.Context, cfg interface{}) (interface{}, error) {
		return New(ctx, cfg.(*reflex.InboundConfig))
	}))
}

func New(ctx context.Context, conf *reflex.InboundConfig) (proxy.Inbound, error) {
	inst := &Handler{
		clients: make([]*protocol.MemoryUser, 0, len(conf.GetClients())),
	}

	for _, usrConf := range conf.GetClients() {
		if usrConf != nil {
			inst.clients = append(inst.clients, &protocol.MemoryUser{
				Email: usrConf.GetId(),
				Account: &MemoryAccount{
					Id:     usrConf.GetId(),
					Policy: usrConf.GetPolicy(),
				},
			})
		}
	}

	if fb := conf.GetFallback(); fb != nil {
		inst.fallback = &FallbackConfig{
			Dest: fb.GetDest(),
		}
	}

	return inst, nil
}