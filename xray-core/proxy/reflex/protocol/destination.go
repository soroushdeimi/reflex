package protocol

import (
	"encoding/binary"
	"errors"

	xnet "github.com/xtls/xray-core/common/net"
)

// ParseDestination extracts address + port from first DATA frame payload.
//
// Format:
// [1 byte addrType]
// [addr]
// [2 byte port]
// [rest payload = actual data]
//
// Returns destination and remaining payload.
func ParseDestination(data []byte) (xnet.Destination, []byte, error) {

	if len(data) < 3 {
		return xnet.Destination{}, nil, errors.New("payload too short")
	}

	addrType := data[0]
	offset := 1

	var address xnet.Address

	switch addrType {

	case AddrTypeIPv4:
		if len(data) < offset+4+2 {
			return xnet.Destination{}, nil, errors.New("invalid ipv4 payload")
		}
		address = xnet.IPAddress(data[offset : offset+4])
		offset += 4

	case AddrTypeIPv6:
		if len(data) < offset+16+2 {
			return xnet.Destination{}, nil, errors.New("invalid ipv6 payload")
		}
		address = xnet.IPAddress(data[offset : offset+16])
		offset += 16

	case AddrTypeDomain:
		domainLen := int(data[offset])
		offset++

		if len(data) < offset+domainLen+2 {
			return xnet.Destination{}, nil, errors.New("invalid domain payload")
		}

		address = xnet.DomainAddress(string(data[offset : offset+domainLen]))
		offset += domainLen

	default:
		return xnet.Destination{}, nil, errors.New("unknown address type")
	}

	port := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	dest := xnet.TCPDestination(address, xnet.Port(port))

	return dest, data[offset:], nil
}
