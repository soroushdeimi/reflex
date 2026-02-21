package inbound

import (
    "context"
    "errors"
    "io"

    "github.com/xtls/xray-core/common"
    "github.com/xtls/xray-core/common/buf"
    "github.com/xtls/xray-core/common/net"
    "github.com/xtls/xray-core/common/session"
    "github.com/xtls/xray-core/common/protocol"
    "github.com/xtls/xray-core/features/routing"
    "github.com/xtls/xray-core/proxy/reflex/encoding"
    "github.com/xtls/xray-core/transport/internet/stat"
)

func init() {
    common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
        return New(ctx, config.(*Config))
    }))
}

type Handler struct {
    // ignored for now
}

func New(ctx context.Context, config *Config) (*Handler, error) {
    return &Handler{}, nil
}

func (h *Handler) Network() []net.Network {
    return []net.Network{net.Network_TCP}
}

func (h *Handler) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
    // will be implemented in step 4
    return nil
}

// handleSession: processes the encrypted session
func (h *Handler) handleSession(ctx context.Context, reader io.Reader, conn stat.Connection, dispatcher routing.Dispatcher, sess *encoding.Session, user *protocol.MemoryUser) error {
    for {
        frame, err := sess.ReadFrame(reader)
        if err != nil {
            if err == io.EOF {
                return nil
            }
            return err
        }

        switch frame.Type {
        case encoding.FrameTypeData:
            err := h.handleData(ctx, frame.Payload, conn, dispatcher, sess, user)
            if err != nil {
                return err
            }
            continue

        case encoding.FrameTypePadding:
            // ignored for now
            continue

        case encoding.FrameTypeTiming:
            // ignored for now
            continue

        case encoding.FrameTypeClose:
            return nil

        default:
            return errors.New("unknown frame type")
        }
    }
}

// handleData: forwards data to upstream and handles responses
func (h *Handler) handleData(ctx context.Context, data []byte, conn stat.Connection, dispatcher routing.Dispatcher, sess *encoding.Session, user *protocol.MemoryUser) error {
    // parse destination from the data frame
    dest, remaining, err := decodeAddress(data)
    if err != nil {
        return err
    }

    // add user info to context for logging/policy
    ctx = session.ContextWithInbound(ctx, &session.Inbound{
        User: user,
    })

    // dispatch to target
    link, err := dispatcher.Dispatch(ctx, dest)
    if err != nil {
        return err
    }

    // send any remaining data that came with the first frame
    if len(remaining) > 0 {
        if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(remaining)}); err != nil {
            return err
        }
    }

    // handle responses from target: read from upstream and send back to client
    go func() {
        defer link.Writer.Close()
        for {
            mb, err := link.Reader.ReadMultiBuffer()
            if err != nil {
                return
            }
            for _, b := range mb {
                if err := sess.WriteFrame(conn, encoding.FrameTypeData, b.Bytes()); err != nil {
                    return
                }
                b.Release()
            }
        }
    }()

    return nil
}

// decodeAddress: parses the destination address from the first data frame
// format: [addrType(1)][port(2)][addr...][remaining data]
// addrType: 1=IPv4, 2=Domain, 3=IPv6
func decodeAddress(data []byte) (net.Destination, []byte, error) {
    if len(data) < 3 {
        return net.Destination{}, nil, errors.New("invalid address data: too short")
    }

    addrType := data[0]
    port := net.PortFromBytes(data[1:3])
    off := 3

    var addr net.Address

    switch addrType {
    case 1: // IPv4
        if len(data) < off+4 {
            return net.Destination{}, nil, errors.New("invalid IPv4 address")
        }
        addr = net.IPAddress(data[off : off+4])
        off += 4

    case 2: // Domain
        if len(data) < off+1 {
            return net.Destination{}, nil, errors.New("invalid domain address")
        }
        domainLen := int(data[off])
        off++
        if len(data) < off+domainLen {
            return net.Destination{}, nil, errors.New("invalid domain address")
        }
        addr = net.DomainAddress(string(data[off : off+domainLen]))
        off += domainLen

    case 3: // IPv6
        if len(data) < off+16 {
            return net.Destination{}, nil, errors.New("invalid IPv6 address")
        }
        addr = net.IPAddress(data[off : off+16])
        off += 16

    default:
        return net.Destination{}, nil, errors.New("unknown address type")
    }

    return net.TCPDestination(addr, port), data[off:], nil
}
