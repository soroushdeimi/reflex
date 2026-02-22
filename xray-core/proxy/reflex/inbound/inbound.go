package inbound

import (
	"bufio"
	"context"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport/internet/stat"
	"google.golang.org/protobuf/proto"
)

const (
	ReflexMinHandshakeSize = 64
)

type Handler struct {
	clients  []*protocol.MemoryUser
	fallback *FallbackConfig
}

type MemoryAccount struct {
	Id string
}

// Equals implements protocol.Account
func (a *MemoryAccount) Equals(account protocol.Account) bool {
	reflexAccount, ok := account.(*MemoryAccount)
	if !ok {
		return false
	}
	return a.Id == reflexAccount.Id
}

// ToProto implements protocol.Account
func (a *MemoryAccount) ToProto() proto.Message {
	return &reflex.Account{
		Id: a.Id,
	}
}

type FallbackConfig struct {
	Dest uint32
}

func (h *Handler) Network() []net.Network {
	return []net.Network{net.Network_TCP}
}

func (h *Handler) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	reader := bufio.NewReader(conn)

	peeked, err := reader.Peek(ReflexMinHandshakeSize)
	if err != nil {
		return err
	}

	if h.isReflexHandshake(peeked) {
		if h.isReflexMagic(peeked) {
			return h.handleReflexMagic(reader, conn, dispatcher, ctx)
		}
		if h.isHTTPPostLike(peeked) {
			return h.handleReflexHTTP(reader, conn, dispatcher, ctx)
		}
		return h.handleFallback(ctx, reader, conn)
	} else {
		return h.handleFallback(ctx, reader, conn)
	}
}
func (h *Handler) isReflexMagic(data []byte) bool {
	if len(data) < 4 {
		return false
	}

	magic := binary.BigEndian.Uint32(data[0:4])
	return magic == reflex.ReflexMagic
}
func (h *Handler) isHTTPPostLike(peeked []byte) bool {
	if len(peeked) < 5 {
		return false
	}
	return string(peeked[:5]) == "POST " || string(peeked[:4]) == "GET " || string(peeked[:4]) == "PUT "
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

func (h *Handler) handleReflexMagic(reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, ctx context.Context) error {
	reader.Discard(4)

	hsBuf := make([]byte, 64)
	if _, err := io.ReadFull(reader, hsBuf); err != nil {
		return err
	}

	var clientHS reflex.ClientHandshake
	copy(clientHS.PublicKey[:], hsBuf[0:32])
	copy(clientHS.UserID[:], hsBuf[32:48])
	clientHS.Timestamp = int64(binary.BigEndian.Uint64(hsBuf[48:56]))
	copy(clientHS.Nonce[:], hsBuf[56:64])

	return h.processHandshake(reader, conn, dispatcher, ctx, clientHS)
}

func (h *Handler) handleReflexHTTP(reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, ctx context.Context) error {
	var clientHS reflex.ClientHandshake
	return h.processHandshake(reader, conn, dispatcher, ctx, clientHS)
}

func (h *Handler) processHandshake(reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, ctx context.Context, clientHS reflex.ClientHandshake) error {
	user, err := h.authenticateUser(clientHS.UserID)
	if err != nil {
		return h.handleFallback(ctx, reader, conn)
	}

	serverPrivateKey, serverPublicKey, err := reflex.GenerateKeyPair()
	if err != nil {
		return err
	}

	sharedKey := reflex.DeriveSharedKey(serverPrivateKey, clientHS.PublicKey)

	salt := make([]byte, 0, 24)
	salt = append(salt, clientHS.Nonce[:]...)
	salt = append(salt, clientHS.UserID[:]...)

	sessionKey, err := reflex.DeriveSessionKey(sharedKey, salt)
	if err != nil {
		return err
	}

	fmt.Printf("DEBUG (Server): SessionKey (first 4 bytes): %x\n", sessionKey[:4])
	fmt.Printf("DEBUG (Server): Salt used (%d bytes): %x\n", len(salt), salt)

	policyData := []byte("access:granted")
	encryptedPolicy, err := h.encryptPolicyGrant(policyData, sessionKey)
	if err != nil {
		return err
	}

	response := make([]byte, 32+2+len(encryptedPolicy))
	copy(response[0:32], serverPublicKey[:])
	binary.BigEndian.PutUint16(response[32:34], uint16(len(encryptedPolicy)))
	copy(response[34:], encryptedPolicy)

	if _, err := conn.Write(response); err != nil {
		return err
	}

	return h.handleSession(ctx, reader, conn, dispatcher, sessionKey, user)
}

func (h *Handler) encryptPolicyGrant(data []byte, key []byte) ([]byte, error) {
	aead, err := reflex.NewCipher(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	return aead.Seal(nil, nonce, data, nil), nil
}

func (h *Handler) handleSession(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, key []byte, user *protocol.MemoryUser) error {
	c2sKey, s2cKey, err := reflex.DeriveDirectionalKeys(key)
	if err != nil {
		return err
	}

	readAEAD, err := reflex.NewCipher(c2sKey)
	if err != nil {
		return err
	}

	writeAEAD, err := reflex.NewCipher(s2cKey)
	if err != nil {
		return err
	}

	inNonce := make([]byte, readAEAD.NonceSize())

	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		return err
	}
	addrLen := binary.BigEndian.Uint16(header)

	encryptedAddr := make([]byte, addrLen)
	if _, err := io.ReadFull(reader, encryptedAddr); err != nil {
		return err
	}

	decryptedAddr, err := readAEAD.Open(nil, inNonce, encryptedAddr, nil)

	if err != nil || len(decryptedAddr) == 0 {
		return errors.New("security block: failed to decrypt target address, dropping connection to prevent panic")
	}

	target, err := net.ParseDestination(string(decryptedAddr))
	if err != nil {
		return fmt.Errorf("invalid target address received: %w", err)
	}

	if !target.IsValid() {
		return fmt.Errorf("security block: parsed destination is invalid (unknown network): %s", target.String())
	}

	fmt.Printf("DEBUG (Server): Forwarding traffic to: %s\n", target.String())

	h.increment(inNonce)

	sessionCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	link, err := dispatcher.Dispatch(sessionCtx, target)
	if err != nil {
		return err
	}

	outNonce := make([]byte, writeAEAD.NonceSize())

	errs := make(chan error, 2)

	go func() {
		errs <- h.readDecrypt(reader, link.Writer, readAEAD, inNonce)
	}()

	go func() {
		errs <- h.encryptWrite(link.Reader, conn, writeAEAD, outNonce)
	}()

	return <-errs
}

func (h *Handler) encryptWrite(reader buf.Reader, writer io.Writer, aead cipher.AEAD, nonce []byte) error {
	for {
		multiBuffer, err := reader.ReadMultiBuffer()
		if err != nil {
			return err
		}
		for _, buffer := range multiBuffer {
			encrypted := aead.Seal(nil, nonce, buffer.Bytes(), nil)
			header := make([]byte, 2)
			binary.BigEndian.PutUint16(header, uint16(len(encrypted)))
			writer.Write(header)
			writer.Write(encrypted)
			h.increment(nonce)
			buffer.Release()
		}
	}
}

func (h *Handler) readDecrypt(reader io.Reader, writer buf.Writer, aead cipher.AEAD, nonce []byte) error {
	header := make([]byte, 3)
	for {
		if _, err := io.ReadFull(reader, header); err != nil {
			return err
		}
		length := binary.BigEndian.Uint16(header[:2])
		fType := header[2]
		
		if fType == reflex.FrameTypeClose {
			return io.EOF
		}

		payload := make([]byte, length)
		if _, err := io.ReadFull(reader, payload); err != nil {
			return err
		}
		decrypted, err := aead.Open(nil, nonce, payload, nil)
		if err != nil {
			return err
		}
		b := buf.New()
		b.Write(decrypted)
		writer.WriteMultiBuffer(buf.MultiBuffer{b})
		h.increment(nonce)
	}
}

func (h *Handler) increment(b []byte) {
	for i := range b {
		b[i]++
		if b[i] != 0 {
			return
		}
	}
}

func (h *Handler) handleFallback(ctx context.Context, reader *bufio.Reader, conn stat.Connection) error {
	if h.fallback == nil || h.fallback.Dest == 0 {
		return errors.New("no fallback configured")
	}

	wrappedConn := &preloadedConn{
		Reader:     reader,
		Connection: conn,
	}

	targetAddr := fmt.Sprintf("127.0.0.1:%d", h.fallback.Dest)
	target, err := net.Dial("tcp", targetAddr)
	if err != nil {
		return fmt.Errorf("failed to dial fallback server: %w", err)
	}
	defer target.Close()

	errs := make(chan error, 2)
	go func() {
		_, err := io.Copy(target, wrappedConn)
		errs <- err
	}()
	go func() {
		_, err := io.Copy(wrappedConn, target)
		errs <- err
	}()

	<-errs
	return nil
}

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

func (pc *preloadedConn) Close() error {
	return pc.Connection.Close()
}

func (h *Handler) authenticateUser(id [16]byte) (*protocol.MemoryUser, error) {
	userIDStr := uuid.UUID(id).String()
	for _, user := range h.clients {
		if user.Account.(*MemoryAccount).Id == userIDStr {
			return user, nil
		}
	}
	return nil, errors.New("user not found")
}

func (h *Handler) formatHTTPResponse(hs reflex.ServerHandshake) []byte {
	return []byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"ok\"}")
}

func init() {
	common.Must(common.RegisterConfig((*reflex.InboundConfig)(nil),
		func(ctx context.Context, config interface{}) (interface{}, error) {
			return New(ctx, config.(*reflex.InboundConfig))
		}))
}

func New(ctx context.Context, config *reflex.InboundConfig) (proxy.Inbound, error) {
	handler := &Handler{
		clients: make([]*protocol.MemoryUser, 0),
	}

	for _, client := range config.Clients {
		handler.clients = append(handler.clients, &protocol.MemoryUser{
			Email:   client.Id,
			Account: &MemoryAccount{Id: client.Id},
		})
	}

	if config.Fallback != nil {
		handler.fallback = &FallbackConfig{
			Dest: config.Fallback.Dest,
		}
	}

	return handler, nil
}
