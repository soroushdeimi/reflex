package outbound

import (
	"bufio"
	"context"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

type Handler struct {
	serverAddress string
	serverPort    net.Port
	clientId      string
}

func (h *Handler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	destination := net.TCPDestination(net.ParseAddress(h.serverAddress), h.serverPort)
	conn, err := dialer.Dial(ctx, destination)
	if err != nil {
		return fmt.Errorf("failed to dial reflex server %s:%d: %w", h.serverAddress, h.serverPort, err)
	}
	defer conn.Close()

	sessionKey, err := h.clientHandshake(conn)
	if err != nil {
		return fmt.Errorf("reflex handshake failed: %w", err)
	}

	c2sKey, s2cKey, err := reflex.DeriveDirectionalKeys(sessionKey)
	if err != nil {
		return fmt.Errorf("failed to derive directional keys: %w", err)
	}

	writeAEAD, err := reflex.NewCipher(c2sKey)
	if err != nil {
		return fmt.Errorf("failed to create write cipher: %w", err)
	}

	readAEAD, err := reflex.NewCipher(s2cKey)
	if err != nil {
		return fmt.Errorf("failed to create read cipher: %w", err)
	}

	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 || !outbounds[0].Target.IsValid() {
		return errors.New("failed to determine target destination")
	}

	targetStr := outbounds[0].Target.String()

	outNonce := make([]byte, writeAEAD.NonceSize())
	encryptedAddr := writeAEAD.Seal(nil, outNonce, []byte(targetStr), nil)

	addrHeader := make([]byte, 2)
	binary.BigEndian.PutUint16(addrHeader, uint16(len(encryptedAddr)))
	if _, err := conn.Write(addrHeader); err != nil {
		return err
	}
	if _, err := conn.Write(encryptedAddr); err != nil {
		return err
	}

	h.increment(outNonce)

	inNonce := make([]byte, readAEAD.NonceSize())
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errs := make(chan error, 2)

	go func() {
		errs <- h.encryptWrite(link.Reader, conn, writeAEAD, outNonce)
	}()

	go func() {
		errs <- h.readDecrypt(conn, link.Writer, readAEAD, inNonce)
	}()

	select {
	case err := <-errs:
		if err != nil && err != io.EOF {
			return err
		}
	case <-ctx.Done():
		return ctx.Err()
	}

	return nil
}

func (h *Handler) encryptWrite(reader buf.Reader, writer io.Writer, aead cipher.AEAD, nonce []byte) error {
	for {
		b, err := reader.ReadMultiBuffer()
		if err != nil {
			return err
		}

		for _, buffer := range b {
			if buffer.IsEmpty() {
				continue
			}

			rawPayload := buffer.Bytes()
			encrypted := aead.Seal(nil, nonce, rawPayload, nil)

			frameHeader := make([]byte, 3)
			binary.BigEndian.PutUint16(frameHeader[:2], uint16(len(encrypted)))
			frameHeader[2] = reflex.FrameTypeData

			if _, err := writer.Write(frameHeader); err != nil {
				return err
			}
			if _, err := writer.Write(encrypted); err != nil {
				return err
			}

			h.increment(nonce)
			buffer.Release()
		}
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

func (h *Handler) readDecrypt(reader io.Reader, writer buf.Writer, aead cipher.AEAD, nonce []byte) error {
	header := make([]byte, 2)

	for {
		if _, err := io.ReadFull(reader, header); err != nil {
			return err
		}
		length := binary.BigEndian.Uint16(header)

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
		if err := writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
			return err
		}

		h.increment(nonce)
	}
}

func (h *Handler) clientHandshake(conn net.Conn) ([]byte, error) {
	privKey, pubKey, err := reflex.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	parsedUUID, err := uuid.ParseString(h.clientId)
	if err != nil {
		return nil, err
	}
	uid := [16]byte(parsedUUID)

	hsPayload := make([]byte, 64)
	copy(hsPayload[0:32], pubKey[:])
	copy(hsPayload[32:48], uid[:])
	binary.BigEndian.PutUint64(hsPayload[48:56], uint64(time.Now().Unix()))

	nonce := make([]byte, 8)
	rand.Read(nonce)
	copy(hsPayload[56:64], nonce)

	fakeHTTP := fmt.Sprintf("POST /api/v1/auth HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Content-Type: application/octet-stream\r\n"+
		"Content-Length: %d\r\n"+
		"Connection: close\r\n\r\n", h.serverAddress, len(hsPayload))

	if _, err := conn.Write([]byte(fakeHTTP)); err != nil {
		return nil, err
	}
	if _, err := conn.Write(hsPayload); err != nil {
		return nil, err
	}

	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil || line == "\r\n" {
			break
		}
	}

	respPubKey := make([]byte, 32)
	io.ReadFull(reader, respPubKey)

	var sPubKey [32]byte
	copy(sPubKey[:], respPubKey)

	shared := reflex.DeriveSharedKey(privKey, sPubKey)
	salt := append(nonce, uid[:]...)
	sessionKey, _ := reflex.DeriveSessionKey(shared, salt)

	policyLenBuf := make([]byte, 2)
	io.ReadFull(reader, policyLenBuf)
	policyLen := binary.BigEndian.Uint16(policyLenBuf)

	encryptedPolicy := make([]byte, policyLen)
	io.ReadFull(reader, encryptedPolicy)

	return sessionKey, nil
}

func New(ctx context.Context, config *reflex.OutboundConfig) (*Handler, error) {
	if config.Address == "" {
		return nil, errors.New("address is required in reflex outbound config")
	}
	if config.Id == "" {
		return nil, errors.New("id (uuid) is required in reflex outbound config")
	}

	return &Handler{
		serverAddress: config.Address,
		serverPort:    net.Port(config.Port),
		clientId:      config.Id,
	}, nil
}

func init() {
	common.Must(common.RegisterConfig(
		(*reflex.OutboundConfig)(nil),
		func(ctx context.Context, config interface{}) (interface{}, error) {
			return New(ctx, config.(*reflex.OutboundConfig))
		},
	))
}
