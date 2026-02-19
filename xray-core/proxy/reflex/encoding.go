package reflex

import (
	"encoding/binary"
	"io"

	"github.com/xtls/xray-core/common/net"
)

// EncodeDestination encodes destination into bytes
func EncodeDestination(dest net.Destination) []byte {
	// Format: [address_type:1][address_length:1][address][port:2]
	var buf []byte

	// Address type (1 = IPv4, 2 = IPv6, 3 = Domain)
	addrBytes := dest.Address.IP()
	if addrBytes != nil {
		if len(addrBytes) == 4 {
			buf = append(buf, 1) // IPv4
			buf = append(buf, 4) // Length
			buf = append(buf, addrBytes...)
		} else {
			buf = append(buf, 2)  // IPv6
			buf = append(buf, 16) // Length
			buf = append(buf, addrBytes...)
		}
	} else {
		domain := dest.Address.Domain()
		buf = append(buf, 3) // Domain
		buf = append(buf, byte(len(domain)))
		buf = append(buf, []byte(domain)...)
	}

	// Port (2 bytes)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(dest.Port))
	buf = append(buf, portBytes...)

	return buf
}

// DecodeDestination decodes destination from bytes
func DecodeDestination(reader io.Reader) (net.Destination, error) {
	// Read address type
	addrType := make([]byte, 1)
	if _, err := io.ReadFull(reader, addrType); err != nil {
		return net.Destination{}, newError("failed to read address type").Base(err)
	}

	// Read address length
	addrLen := make([]byte, 1)
	if _, err := io.ReadFull(reader, addrLen); err != nil {
		return net.Destination{}, newError("failed to read address length").Base(err)
	}

	// Read address
	addrBytes := make([]byte, addrLen[0])
	if _, err := io.ReadFull(reader, addrBytes); err != nil {
		return net.Destination{}, newError("failed to read address").Base(err)
	}

	// Parse address
	var address net.Address
	switch addrType[0] {
	case 1: // IPv4
		address = net.IPAddress(addrBytes)
	case 2: // IPv6
		address = net.IPAddress(addrBytes)
	case 3: // Domain
		address = net.DomainAddress(string(addrBytes))
	default:
		return net.Destination{}, newError("invalid address type: ", addrType[0])
	}

	// Read port
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(reader, portBytes); err != nil {
		return net.Destination{}, newError("failed to read port").Base(err)
	}
	port := net.Port(binary.BigEndian.Uint16(portBytes))

	return net.TCPDestination(address, port), nil
}
