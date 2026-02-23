package inbound

import (
	"bufio"
	"context"
	"io"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// parseDestination extracts destination from frame payload
// Format: [address_type (1 byte)] [address] [port (2 bytes, big-endian)]
func parseDestination(data []byte) (net.Destination, error) {
	if len(data) < 3 {
		return net.Destination{}, errors.New("destination data too short")
	}

	addrType := data[0]
	var address net.Address
	var port net.Port

	switch addrType {
	case 0x01: // IPv4
		if len(data) < 7 {
			return net.Destination{}, errors.New("invalid IPv4 address")
		}
		address = net.IPAddress(data[1:5])
		port = net.PortFromBytes(data[5:7])

	case 0x02: // IPv6
		if len(data) < 19 {
			return net.Destination{}, errors.New("invalid IPv6 address")
		}
		address = net.IPAddress(data[1:17])
		port = net.PortFromBytes(data[17:19])

	case 0x03: // Domain name
		if len(data) < 2 {
			return net.Destination{}, errors.New("invalid domain name length")
		}
		domainLen := int(data[1])
		if len(data) < 4+domainLen {
			return net.Destination{}, errors.New("invalid domain name")
		}
		domain := string(data[2 : 2+domainLen])
		address = net.DomainAddress(domain)
		port = net.PortFromBytes(data[2+domainLen : 4+domainLen])

	default:
		return net.Destination{}, errors.New("unknown address type")
	}

	return net.TCPDestination(address, port), nil
}

// handleData processes a data frame and forwards it to upstream
func (h *Handler) handleData(ctx context.Context, data []byte, conn stat.Connection, dispatcher routing.Dispatcher, sess *Session, user *protocol.MemoryUser, reader *bufio.Reader) error {
	// Parse destination from first frame
	dest, err := parseDestination(data)
	if err != nil {
		return errors.New("failed to parse destination").Base(err)
	}

	// Get policy manager
	v := core.MustFromContext(ctx)
	policyManager := v.GetFeature(policy.ManagerType()).(policy.Manager)
	plcy := policyManager.ForLevel(user.Level)

	// Set up context with user
	inbound := session.InboundFromContext(ctx)
	if inbound == nil {
		inbound = new(session.Inbound)
	}
	inbound.User = user
	ctx = session.ContextWithInbound(ctx, inbound)

	// Log access
	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   conn.RemoteAddr(),
		To:     dest,
		Status: log.AccessAccepted,
		Email:  user.Email,
	})

	// Dispatch to upstream
	link, err := dispatcher.Dispatch(ctx, dest)
	if err != nil {
		return errors.New("failed to dispatch connection").Base(err)
	}

	// Set up timeout
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, cancel, plcy.Timeouts.ConnectionIdle)
	defer timer.SetTimeout(0)

	// Forward data to upstream
	requestDone := func() error {
		defer timer.SetTimeout(plcy.Timeouts.DownlinkOnly)
		
		// Write the data (excluding destination header) to upstream
		destLen := getDestinationLength(data)
		if len(data) > destLen {
			payload := data[destLen:]
			buffer := buf.FromBytes(payload)
			if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{buffer}); err != nil {
				return errors.New("failed to write request").Base(err)
			}
		}
		
		// Continue reading frames from client and forwarding to upstream
		for {
			frame, err := sess.ReadFrame(reader)
			if err != nil {
				if err == io.EOF {
					return nil
				}
				return errors.New("failed to read frame").Base(err)
			}

			switch frame.Type {
			case FrameTypeData:
				// Forward data to upstream
				buffer := buf.FromBytes(frame.Payload)
				if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{buffer}); err != nil {
					return errors.New("failed to write to upstream").Base(err)
				}
			case FrameTypeClose:
				return nil
			case FrameTypePadding, FrameTypeTiming:
				// Ignore control frames
				continue
			default:
				return errors.New("unknown frame type in data stream")
			}
		}
	}

	// Forward response from upstream to client
	responseDone := func() error {
		defer timer.SetTimeout(plcy.Timeouts.UplinkOnly)
		
		writer := &sessionWriter{
			session: sess,
			conn:    conn,
		}
		return buf.Copy(link.Reader, writer, buf.UpdateActivity(timer))
	}

	// Run both directions concurrently
	requestDonePost := task.OnSuccess(requestDone, task.Close(link.Writer))
	if err := task.Run(ctx, requestDonePost, responseDone); err != nil {
		_ = common.Interrupt(link.Reader)
		_ = common.Interrupt(link.Writer)
		return errors.New("connection ends").Base(err)
	}

	return nil
}

// getDestinationLength calculates the length of destination header
func getDestinationLength(data []byte) int {
	if len(data) < 1 {
		return 0
	}

	addrType := data[0]
	switch addrType {
	case 0x01: // IPv4
		return 7
	case 0x02: // IPv6
		return 19
	case 0x03: // Domain name
		if len(data) < 2 {
			return 0
		}
		domainLen := int(data[1])
		return 4 + domainLen
	default:
		return 0
	}
}

// sessionWriter wraps connection to write encrypted frames
type sessionWriter struct {
	session *Session
	conn    stat.Connection
}

func (w *sessionWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	
	for _, b := range mb {
		var err error
		if w.session.morphingEnabled && w.session.profile != nil {
			// Use morphing if enabled
			err = w.session.WriteFrameWithMorphing(w.conn, FrameTypeData, b.Bytes(), w.session.profile)
		} else {
			// Use regular WriteFrame
			err = w.session.WriteFrame(w.conn, FrameTypeData, b.Bytes())
		}
		if err != nil {
			return err
		}
	}
	return nil
}

