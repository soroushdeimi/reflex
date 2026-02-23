package reflex

import (
	"encoding/binary"
	"errors"

	"github.com/xtls/xray-core/common/net"
)

var ErrNeedMore = errors.New("need more bytes")

func ParseDestFromPayload(payload []byte) (net.Destination, []byte, error) {
	if len(payload) < 1+2 {
		return net.Destination{}, nil, ErrNeedMore
	}

	at := payload[0]
	p := payload[1:]

	var addr net.Address

	switch at {
	case 1: // IPv4
		if len(p) < 4+2 {
			return net.Destination{}, nil, ErrNeedMore
		}
		addr = net.IPAddress(p[:4])
		p = p[4:]

	case 3: // IPv6
		if len(p) < 16+2 {
			return net.Destination{}, nil, ErrNeedMore
		}
		addr = net.IPAddress(p[:16])
		p = p[16:]

	case 2:
		if len(p) < 1+2 {
			return net.Destination{}, nil, ErrNeedMore
		}
		l := int(p[0])
		p = p[1:]
		if len(p) < l+2 {
			return net.Destination{}, nil, ErrNeedMore
		}
		addr = net.DomainAddress(string(p[:l]))
		p = p[l:]

	default:
		return net.Destination{}, nil, errors.New("unknown address type")
	}

	port := binary.BigEndian.Uint16(p[:2])
	rest := p[2:]

	return net.TCPDestination(addr, net.Port(port)), rest, nil
}
