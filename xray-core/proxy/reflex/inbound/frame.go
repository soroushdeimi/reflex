package inbound

import (
	"bufio"
	"context"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/stat"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	FrameTypeData    = 0x01
	FrameTypePadding = 0x02
	FrameTypeTiming  = 0x03
	FrameTypeClose   = 0x04
)

type Frame struct {
	Length  uint16
	Type    uint8
	Payload []byte
}

type Session struct {
	key        []byte
	aead       cipher.AEAD
	readNonce  uint64
	writeNonce uint64
}

func NewSession(sessionKey []byte) (*Session, error) {
	aead, err := chacha20poly1305.New(sessionKey)
	if err != nil {
		return nil, err
	}

	return &Session{
		key:        sessionKey,
		aead:       aead,
		readNonce:  0,
		writeNonce: 0,
	}, nil
}

func (s *Session) ReadFrame(reader io.Reader) (*Frame, error) {
    // خواندن header (3 بایت)
    header := make([]byte, 3)
    if _, err := io.ReadFull(reader, header); err != nil {
        return nil, err
    }
    
    length := binary.BigEndian.Uint16(header[0:2])
    frameType := header[2]
    
    // خواندن payload
    encryptedPayload := make([]byte, length)
    if _, err := io.ReadFull(reader, encryptedPayload); err != nil {
        return nil, err
    }
    
    // رمزگشایی
    nonce := make([]byte, 12)
    binary.BigEndian.PutUint64(nonce[4:], s.readNonce)
    s.readNonce++
    
    payload, err := s.aead.Open(nil, nonce, encryptedPayload, nil)
    if err != nil {
        return nil, err
    }
    
    return &Frame{
        Length: length,
        Type: frameType,
        Payload: payload,
    }, nil
}

func (s *Session) WriteFrame(writer io.Writer, frameType uint8, data []byte) error {
    // رمزنگاری
    nonce := make([]byte, 12)
    binary.BigEndian.PutUint64(nonce[4:], s.writeNonce)
    s.writeNonce++
    
    encrypted := s.aead.Seal(nil, nonce, data, nil)
    
    // نوشتن header
    header := make([]byte, 3)
    binary.BigEndian.PutUint16(header[0:2], uint16(len(encrypted)))
    header[2] = frameType
    
    if _, err := writer.Write(header); err != nil {
        return err
    }
    
    // نوشتن payload
    if _, err := writer.Write(encrypted); err != nil {
        return err
    }
    
    return nil
}

func (h *Handler) handleSession(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, sessionKey []byte, user *protocol.MemoryUser) error {
    session, err := NewSession(sessionKey)
    if err != nil {
        return err
    }
    
    for {
        frame, err := session.ReadFrame(reader)
        if err != nil {
            return err
        }
        
        switch frame.Type {
        case FrameTypeData:
            err := h.handleData(ctx, frame.Payload, conn, dispatcher, session, user)
            if err != nil {
                return err
            }
            // ادامه خواندن frame‌های بعدی
            continue
            
        case FrameTypePadding:
            // دستور padding - فعلاً نادیده می‌گیریم
            continue
            
        case FrameTypeTiming:
            // دستور timing - فعلاً نادیده می‌گیریم
            continue
            
        case FrameTypeClose:
            // بستن اتصال
            return nil
            
        default:
            return errors.New("unknown frame type")
        }
    }
}

func (h *Handler) handleData(ctx context.Context, data []byte, conn stat.Connection, dispatcher routing.Dispatcher, session *Session, user *protocol.MemoryUser) error {
    if len(data) < 3 {
        return errors.New("invalid payload")
    }

    var addr net.Address
    var port net.Port
    var offset int

    atyp := data[0]
    offset = 1

    switch atyp {

		case 1: // IPv4
			if len(data) < offset+4+2 {
				return errors.New("invalid ipv4 payload")
			}
			ip := net.IP(data[offset : offset+4])
			addr = net.IPAddress(ip)
			offset += 4

		case 2: // Domain
			domainLen := int(data[offset])
			offset++

			if len(data) < offset+domainLen+2 {
				return errors.New("invalid domain payload")
			}

			domain := string(data[offset : offset+domainLen])
			addr = net.ParseAddress(domain)
			offset += domainLen

		default:
			return errors.New("unknown address type")
    }

    // Port (2 bytes big endian)
    port = net.Port(binary.BigEndian.Uint16(data[offset : offset+2]))
    offset += 2

    // Remaining data
    payload := data[offset:]

    dest := net.TCPDestination(addr, port)

    link, err := dispatcher.Dispatch(ctx, dest)
    if err != nil {
        return err
    }

    // upstream -> client
    go func() {
        defer common.Close(link.Writer)

        for {
            mb, err := link.Reader.ReadMultiBuffer()
            if err != nil {
                return
            }

            for _, b := range mb {
                if err := session.WriteFrame(conn, FrameTypeData, b.Bytes()); err != nil {
                    b.Release()
                    return
                }
                b.Release()
            }
        }
    }()

    if len(payload) > 0 {
        buffer := buf.FromBytes(payload)
        if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{buffer}); err != nil {
            return err
        }
    }

    return nil
}