package tunnel

import (
	"encoding/binary"

	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
)

// DestinationCodec encodes/decodes destination headers carried inside the first DATA frame.
//
// We intentionally keep this as an interface so that if the course spec changes (or Step4/5 needs
// extensions), we can swap the codec without touching the Session / Pipe logic.
type DestinationCodec interface {
	Encode(dest xnet.Destination) ([]byte, error)
	Decode(payload []byte) (dest xnet.Destination, headerLen int, err error)
}

// SocksAddrCodec encodes destination in a SOCKS5-like format:
//
//   [ATYP][DST.ADDR][DST.PORT]
//
// ATYP:
//   0x01 = IPv4 (4 bytes)
//   0x03 = Domain (1 byte length + domain bytes)
//   0x04 = IPv6 (16 bytes)
//
// Port is big-endian uint16.
//
// Note: This codec currently assumes TCP as the network for decoded destinations.
// (If future steps require UDP support, we can extend the format with a leading network byte
// or a versioned header, without changing other parts of Step3.)
type SocksAddrCodec struct{}

const (
	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04
)

func (SocksAddrCodec) Encode(dest xnet.Destination) ([]byte, error) {
	if !dest.IsValid() {
		return nil, errors.New("reflex tunnel: invalid destination")
	}

	switch dest.Address.Family() {
	case xnet.AddressFamilyIPv4:
		ip := dest.Address.IP().To4()
		if ip == nil || len(ip) != 4 {
			return nil, errors.New("reflex tunnel: invalid ipv4 address")
		}
		out := make([]byte, 1+4+2)
		out[0] = atypIPv4
		copy(out[1:5], ip)
		binary.BigEndian.PutUint16(out[5:7], uint16(dest.Port))
		return out, nil

	case xnet.AddressFamilyIPv6:
		ip := dest.Address.IP().To16()
		if ip == nil || len(ip) != 16 {
			return nil, errors.New("reflex tunnel: invalid ipv6 address")
		}
		out := make([]byte, 1+16+2)
		out[0] = atypIPv6
		copy(out[1:17], ip)
		binary.BigEndian.PutUint16(out[17:19], uint16(dest.Port))
		return out, nil

	case xnet.AddressFamilyDomain:
		d := dest.Address.Domain()
		if len(d) == 0 {
			return nil, errors.New("reflex tunnel: empty domain")
		}
		if len(d) > 255 {
			return nil, errors.New("reflex tunnel: domain too long")
		}
		out := make([]byte, 1+1+len(d)+2)
		out[0] = atypDomain
		out[1] = byte(len(d))
		copy(out[2:2+len(d)], []byte(d))
		binary.BigEndian.PutUint16(out[2+len(d):2+len(d)+2], uint16(dest.Port))
		return out, nil

	default:
		return nil, errors.New("reflex tunnel: unsupported address family")
	}
}

func (SocksAddrCodec) Decode(payload []byte) (xnet.Destination, int, error) {
	if len(payload) < 1 {
		return xnet.Destination{}, 0, errors.New("reflex tunnel: destination header too short")
	}

	atyp := payload[0]
	switch atyp {
	case atypIPv4:
		const need = 1 + 4 + 2
		if len(payload) < need {
			return xnet.Destination{}, 0, errors.New("reflex tunnel: ipv4 header too short")
		}
		ip := payload[1:5]
		port := binary.BigEndian.Uint16(payload[5:7])
		dest := xnet.TCPDestination(xnet.IPAddress(ip), xnet.Port(port))
		return dest, need, nil

	case atypIPv6:
		const need = 1 + 16 + 2
		if len(payload) < need {
			return xnet.Destination{}, 0, errors.New("reflex tunnel: ipv6 header too short")
		}
		ip := payload[1:17]
		port := binary.BigEndian.Uint16(payload[17:19])
		dest := xnet.TCPDestination(xnet.IPAddress(ip), xnet.Port(port))
		return dest, need, nil

	case atypDomain:
		if len(payload) < 2 {
			return xnet.Destination{}, 0, errors.New("reflex tunnel: domain header too short")
		}
		dlen := int(payload[1])
		if dlen == 0 {
			return xnet.Destination{}, 0, errors.New("reflex tunnel: empty domain in header")
		}
		need := 1 + 1 + dlen + 2
		if len(payload) < need {
			return xnet.Destination{}, 0, errors.New("reflex tunnel: domain header too short")
		}
		domain := string(payload[2 : 2+dlen])
		port := binary.BigEndian.Uint16(payload[2+dlen : 2+dlen+2])
		dest := xnet.TCPDestination(xnet.DomainAddress(domain), xnet.Port(port))
		return dest, need, nil

	default:
		return xnet.Destination{}, 0, errors.New("reflex tunnel: unknown address type")
	}
}
