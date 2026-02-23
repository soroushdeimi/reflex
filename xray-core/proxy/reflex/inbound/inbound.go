package inbound

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	stdnet "net"
	"strings"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	reflexpb "github.com/xtls/xray-core/proxy/reflex"
	reflexcrypto "github.com/xtls/xray-core/proxy/reflex/crypto"
	reflexproto "github.com/xtls/xray-core/proxy/reflex/protocol"
	"github.com/xtls/xray-core/proxy/reflex/session"
	"github.com/xtls/xray-core/transport/internet/stat"
	"google.golang.org/protobuf/proto"
)

// Handler processes inbound reflex connections.
type Handler struct {
	clients  []*protocol.MemoryUser
	fallback *FallbackConfig
}

// MemoryAccount implements protocol.Account (simple wrapper around id)
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
	return &reflexpb.Account{
		Id: a.Id,
	}
}

type FallbackConfig struct {
	Dest uint32
}

func (h *Handler) Network() []xnet.Network {
	return []xnet.Network{xnet.Network_TCP}
}

// Process is the inbound entry. It peeks a few bytes to detect reflex vs fallback,
// and either handles reflex or proxies the whole connection to fallback.
func (h *Handler) Process(
	ctx context.Context,
	network xnet.Network,
	conn stat.Connection,
	dispatcher routing.Dispatcher,
) error {

	// Wrap connection in bufio.Reader so we can peek without consuming bytes
	reader := bufio.NewReader(conn)

	// minimum bytes for detection (magic or "POST")
	const minPeek = 8
	peeked, err := reader.Peek(minPeek)
	if err != nil && err != io.EOF {
		return err
	}

	isMagic := false
	if len(peeked) >= 4 {
		if binary.BigEndian.Uint32(peeked[0:4]) == reflexcrypto.ReflexMagic {
			isMagic = true
		}
	}

	isPost := false
	if len(peeked) >= 4 {
		if strings.HasPrefix(string(peeked[:4]), "POST") {
			isPost = true
		}
	}

	if isMagic || isPost {
		// REFX connection: handle with ServerHandshake.
		// On failure, drainAndError already wrote HTTP error to client.
		// Never fall back a REFX connection - fallback is only for non-Reflex traffic.
		sess, user, err := reflexcrypto.ServerHandshake(reader, conn, h.clients)
		if err != nil {
			return err
		}
		if sess == nil {
			return errors.New("nil session after handshake")
		}

		return h.handleSession(ctx, reader, conn, dispatcher, sess, user)
	}

	// Not reflex -> fallback
	return h.handleFallback(ctx, reader, conn)
}

// handleSession processes encrypted frames after a successful handshake.
// Reads the first DATA frame for destination, dispatches, then bridges traffic.
func (h *Handler) handleSession(
	ctx context.Context,
	reader *bufio.Reader,
	conn stat.Connection,
	dispatcher routing.Dispatcher,
	sess *session.Session,
	user *protocol.MemoryUser,
) error {
	_ = user

	// Read the first frame — must be DATA containing destination header
	firstFrame, err := sess.ReadFrame(reader)
	if err != nil {
		return fmt.Errorf("read first frame: %w", err)
	}

	if firstFrame.Type == session.FrameTypeClose {
		return nil
	}

	if firstFrame.Type != session.FrameTypeData {
		return errors.New("expected DATA frame as first frame")
	}

	// Parse destination from first DATA frame payload
	dest, remainingData, err := reflexproto.ParseDestination(firstFrame.Payload)
	if err != nil {
		return fmt.Errorf("parse destination: %w", err)
	}

	// Dispatch to outbound
	link, err := dispatcher.Dispatch(ctx, dest)
	if err != nil {
		return fmt.Errorf("dispatch: %w", err)
	}

	// Write any remaining data from the first frame to outbound
	if len(remainingData) > 0 {
		mb := buf.MultiBuffer{buf.FromBytes(remainingData)}
		if err := link.Writer.WriteMultiBuffer(mb); err != nil {
			return fmt.Errorf("write initial data: %w", err)
		}
	}

	// Bridge inbound frames → outbound writer
	inboundDone := make(chan error, 1)
	go func() {
		for {
			frame, err := sess.ReadFrame(reader)
			if err != nil {
				inboundDone <- err
				return
			}
			switch frame.Type {
			case session.FrameTypeClose:
				inboundDone <- nil
				return
			case session.FrameTypePadding, session.FrameTypeTiming:
				// Morphing control frames: skip payload
				continue
			case session.FrameTypeData:
				mb := buf.MultiBuffer{buf.FromBytes(frame.Payload)}
				if err := link.Writer.WriteMultiBuffer(mb); err != nil {
					inboundDone <- err
					return
				}
			}
		}
	}()

	// Bridge outbound reader → inbound frames
	outboundDone := make(chan error, 1)
	go func() {
		for {
			mb, err := link.Reader.ReadMultiBuffer()
			if err != nil {
				outboundDone <- err
				return
			}
			for _, b := range mb {
				if writeErr := sess.WriteFrame(conn, session.FrameTypeData, b.Bytes()); writeErr != nil {
					b.Release()
					buf.ReleaseMulti(mb)
					outboundDone <- writeErr
					return
				}
				b.Release()
			}
		}
	}()

	select {
	case err = <-inboundDone:
	case err = <-outboundDone:
	}

	// Send CLOSE frame on clean shutdown
	_ = sess.WriteFrame(conn, session.FrameTypeClose, nil)
	return err
}

// preloadedConn wraps bufio.Reader over stat.Connection so peeked bytes
// are replayed when the fallback server reads from the connection.
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
		conn.Close()
		return errors.New("no fallback configured")
	}

	// FIX: Use stdlib stdnet.Dial (xray's net package has no Dial function)
	targetAddr := fmt.Sprintf("127.0.0.1:%d", h.fallback.Dest)
	target, err := stdnet.Dial("tcp", targetAddr)
	if err != nil {
		return err
	}
	defer target.Close()

	wrapped := &preloadedConn{
		Reader:     reader,
		Connection: conn,
	}

	go func() {
		defer target.Close()
		io.Copy(target, wrapped)
	}()
	_, err = io.Copy(wrapped, target)
	return err
}

func init() {
	common.Must(common.RegisterConfig((*reflexpb.InboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*reflexpb.InboundConfig))
	}))
}

// New builds Handler from protobuf config
func New(ctx context.Context, config *reflexpb.InboundConfig) (proxy.Inbound, error) {
	handler := &Handler{
		clients: make([]*protocol.MemoryUser, 0),
	}

	for _, c := range config.Clients {
		handler.clients = append(handler.clients, &protocol.MemoryUser{
			Email:   c.Id,
			Account: &MemoryAccount{Id: c.Id},
		})
	}

	if config.Fallback != nil {
		handler.fallback = &FallbackConfig{
			Dest: config.Fallback.Dest,
		}
	}

	return handler, nil
}
