package inbound

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport/internet/stat"
	"google.golang.org/protobuf/proto"
)

const ReflexMinHandshakeSize = 64

type Handler struct {
	clients  []*protocol.MemoryUser
	fallback *FallbackConfig
}

type MemoryAccount struct {
	Id string
}

func (a *MemoryAccount) Equals(account protocol.Account) bool {
	reflexAccount, ok := account.(*MemoryAccount)
	if !ok {
		return false
	}
	return a.Id == reflexAccount.Id
}

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
		if len(peeked) >= 4 {
			magic := binary.BigEndian.Uint32(peeked[0:4])
			if magic == reflex.ReflexMagic {
				// TODO: Handle Reflex Magic
				return nil
			}
		}
		if h.isHTTPPostLike(peeked) {
			// TODO: Handle Reflex Magic
			return nil
		}
		// TODO: Handle Fallback
		return nil
	} else {
		// TODO: Handle Fallback
		return nil
	}
}

func (h *Handler) isReflexMagic(data []byte) bool {
	if len(data) < 4 {
		return false
	}

	magic := binary.BigEndian.Uint32(data[0:4])
	return magic == reflex.ReflexMagic
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

func (h *Handler) authenticateUser(userID [16]byte) (*protocol.MemoryUser, error) {
	userUUID, err := uuid.ParseBytes(userID[:])
	if err != nil {
		return nil, errors.New("invalid user ID format")
	}
	userIDStr := userUUID.String()

	for _, user := range h.clients {
		if user.Account.(*MemoryAccount).Id == userIDStr {
			return user, nil
		}
	}
	return nil, errors.New("user not found")
}

func (h *Handler) sendErrorResponse(conn stat.Connection, statusCode int, message string) {
	response := fmt.Sprintf("HTTP/1.1 %d %s\r\nConnection: close\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s",
		statusCode, message, len(message), message)
	conn.Write([]byte(response))
}

func (h *Handler) handleError(ctx context.Context, conn stat.Connection, err error, statusCode int) error {
	if statusCode == 0 {
		statusCode = 403
	}

	errorMsg := "Forbidden"
	if statusCode == 400 {
		errorMsg = "Bad Request"
	} else if statusCode == 401 {
		errorMsg = "Unauthorized"
	} else if statusCode == 500 {
		errorMsg = "Internal Server Error"
	}

	h.sendErrorResponse(conn, statusCode, errorMsg)

	if err != nil && errors.Cause(err) != io.EOF {
		log.Record(&log.AccessMessage{
			From:   conn.RemoteAddr(),
			To:     "",
			Status: log.AccessRejected,
			Reason: err,
		})
		err = errors.New("reflex handshake failed").Base(err).AtInfo()
		errors.LogInfo(ctx, err.Error())
	}

	return err
}

func (h *Handler) handleSession(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, sessionKey []byte, user *protocol.MemoryUser) error {
	session, err := reflex.NewSession(sessionKey)
	if err != nil {
		return err
	}

	for {
		frame, err := session.ReadFrame(reader)
		if err != nil {
			return err
		}

		switch frame.Type {
		case reflex.FrameTypeData:
			err := h.handleData(ctx, frame.Payload, conn, dispatcher, session, user)
			if err != nil {
				return err
			}
			continue

		case reflex.FrameTypePadding:
			continue

		case reflex.FrameTypeTiming:
			continue

		case reflex.FrameTypeClose:
			return nil

		default:
			return errors.New("unknown frame type")
		}
	}
}

func (h *Handler) handleData(ctx context.Context, data []byte, conn stat.Connection, dispatcher routing.Dispatcher, session *reflex.Session, user *protocol.MemoryUser) error {
	dest := net.TCPDestination(net.ParseAddress("example.com"), net.Port(80))

	link, err := dispatcher.Dispatch(ctx, dest)
	if err != nil {
		return err
	}

	buffer := buf.FromBytes(data)
	if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{buffer}); err != nil {
		return err
	}

	go func() {
		// I saw this in proxy/http/server.go:254, so I'm doing it here too
		defer common.Close(link.Writer)
		for {
			mb, err := link.Reader.ReadMultiBuffer()
			if err != nil {
				return
			}
			for _, b := range mb {
				if err := session.WriteFrame(conn, reflex.FrameTypeData, b.Bytes()); err != nil {
					b.Release()
					return
				}
				b.Release()
			}
		}
	}()

	return nil
}

func init() {
	common.Must(common.RegisterConfig((*reflex.InboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*reflex.InboundConfig))
	}))
}

func New(ctx context.Context, config *reflex.InboundConfig) (proxy.Inbound, error) {
	handler := &Handler{
		clients: make([]*protocol.MemoryUser, 0),
	}

	// تبدیل config به handler
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
