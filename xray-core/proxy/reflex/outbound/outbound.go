package outbound

import (
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
	"github.com/xtls/xray-core/common/retry"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

type Handler struct {
	serverAddress net.Destination
	clientId      string
}

func (h *Handler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	var conn net.Conn
	err := retry.ExponentialBackoff(5, 100).On(func() error {
		rawConn, err := dialer.Dial(ctx, h.serverAddress)
		if err != nil {
			return err
		}
		conn = rawConn
		return nil
	})
	if err != nil {
		return err
	}
	defer conn.Close()

	// Step 2: Handshake
	sessionKey, err := h.clientHandshake(conn)
	if err != nil {
		return err
	}

	// Step 3: Encryption Setup
	aead, err := reflex.NewCipher(sessionKey)
	if err != nil {
		return err
	}

	// Bidirectional relay  with encryption
	ctx, cancel := context.WithCancel(ctx)
	defer cancel() // Ensure resources are freed

	// Upload: Client -> Server
	go func() {
		_ = h.encryptWrite(link.Reader, conn, aead)
		cancel()
	}()

	// Download: Server -> Client
	_ = h.readDecrypt(conn, link.Writer, aead)
	cancel()

	return nil
}

// encryptWrite reads raw data and writes encrypted frames
func (h *Handler) encryptWrite(reader buf.Reader, writer io.Writer, aead cipher.AEAD) error {
	nonce := make([]byte, aead.NonceSize())
	// Use static salt/counter for nonce in this step

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
			// Frame: [2B Length][Encrypted Payload + 16B Tag]
			encrypted := aead.Seal(nil, nonce, rawPayload, nil)

			frameHeader := make([]byte, 2)
			binary.BigEndian.PutUint16(frameHeader, uint16(len(encrypted)))

			if _, err := writer.Write(frameHeader); err != nil {
				return err
			}
			if _, err := writer.Write(encrypted); err != nil {
				return err
			}

			// Increment nonce to prevent reuse
			increment(nonce)
			buffer.Release()
		}
	}
}

// readDecrypt reads encrypted frames and writes raw data
func (h *Handler) readDecrypt(reader io.Reader, writer buf.Writer, aead cipher.AEAD) error {
	nonce := make([]byte, aead.NonceSize())
	header := make([]byte, 2)

	for {
		// Read frame length
		if _, err := io.ReadFull(reader, header); err != nil {
			return err
		}
		length := binary.BigEndian.Uint16(header)

		// Read encrypted payload + tag
		payload := make([]byte, length)
		if _, err := io.ReadFull(reader, payload); err != nil {
			return err
		}

		// Decrypt
		decrypted, err := aead.Open(nil, nonce, payload, nil)
		if err != nil {
			return err
		}

		// Write back to user
		b := buf.New()
		b.Write(decrypted)
		if err := writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
			return err
		}

		increment(nonce)
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

	fullPayload := make([]byte, 4+64)
	binary.BigEndian.PutUint32(fullPayload[:4], reflex.ReflexMagic)
	copy(fullPayload[4:36], pubKey[:])
	uid := [16]byte(parsedUUID)
	copy(fullPayload[36:52], uid[:])
	binary.BigEndian.PutUint64(fullPayload[52:60], uint64(time.Now().Unix()))
	if _, err := rand.Read(fullPayload[60:68]); err != nil {
		return nil, err
	}

	if _, err := conn.Write(fullPayload); err != nil {
		return nil, err
	}

	respPubKey := make([]byte, 32)
	if _, err := io.ReadFull(conn, respPubKey); err != nil {
		return nil, err
	}

	var sPubKey [32]byte
	copy(sPubKey[:], respPubKey)

	shared := reflex.DeriveSharedKey(privKey, sPubKey)
	salt := append(fullPayload[60:68], uid[:]...)
	sessionKey, err := reflex.DeriveSessionKey(shared, salt)
	if err != nil {
		return nil, err
	}

	policyLenBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, policyLenBuf); err != nil {
		return nil, fmt.Errorf("failed to read policy length: %w", err)
	}
	policyLen := binary.BigEndian.Uint16(policyLenBuf)

	encryptedPolicy := make([]byte, policyLen)
	if _, err := io.ReadFull(conn, encryptedPolicy); err != nil {
		return nil, fmt.Errorf("failed to read encrypted policy: %w", err)
	}

	policyAead, err := reflex.NewCipher(sessionKey)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, policyAead.NonceSize())

	decryptedPolicy, err := policyAead.Open(nil, nonce, encryptedPolicy, nil)
	if err != nil {
		return nil, errors.New("failed to decrypt policy grant")
	}

	fmt.Printf("Policy Grant received: %d bytes\n", len(decryptedPolicy))

	return sessionKey, nil
}

func New(ctx context.Context, config *reflex.OutboundConfig) (proxy.Outbound, error) {
	return &Handler{
		serverAddress: net.Destination{
			Network: net.Network_TCP,
			Address: net.ParseAddress(config.Address),
			Port:    net.Port(config.Port),
		},
		clientId: config.Id,
	}, nil
}

// increment is a helper to increase the nonce counter to prevent reuse
func increment(b []byte) {
	for i := range b {
		b[i]++
		if b[i] != 0 {
			return
		}
	}
}

func init() {
	common.Must(common.RegisterConfig(
		(*reflex.OutboundConfig)(nil),
		func(ctx context.Context, config interface{}) (interface{}, error) {
			return New(ctx, config.(*reflex.OutboundConfig))
		},
	))
}
