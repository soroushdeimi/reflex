package outbound

import (
	"encoding/binary"
	"net"
	"testing"

	xnet "github.com/xtls/xray-core/common/net"
)

func TestMarshalDestinationIPv4(t *testing.T) {
	dest := xnet.TCPDestination(xnet.IPAddress(net.ParseIP("192.168.1.1").To4()), 8080)
	data := marshalDestination(dest)

	if data[0] != 1 {
		t.Fatalf("expected addrType 1 (IPv4), got %d", data[0])
	}
	if data[1] != 192 || data[2] != 168 || data[3] != 1 || data[4] != 1 {
		t.Fatalf("unexpected IP bytes: %v", data[1:5])
	}
	port := binary.BigEndian.Uint16(data[5:7])
	if port != 8080 {
		t.Fatalf("expected port 8080, got %d", port)
	}
}

func TestMarshalDestinationIPv6(t *testing.T) {
	ipv6 := net.ParseIP("::1").To16()
	dest := xnet.TCPDestination(xnet.IPAddress(ipv6), 443)
	data := marshalDestination(dest)

	if data[0] != 3 {
		t.Fatalf("expected addrType 3 (IPv6), got %d", data[0])
	}
	// 1 (type) + 16 (IPv6) + 2 (port) = 19 bytes
	if len(data) != 19 {
		t.Fatalf("expected 19 bytes, got %d", len(data))
	}
	port := binary.BigEndian.Uint16(data[17:19])
	if port != 443 {
		t.Fatalf("expected port 443, got %d", port)
	}
}

func TestMarshalDestinationDomain(t *testing.T) {
	dest := xnet.TCPDestination(xnet.DomainAddress("example.com"), 80)
	data := marshalDestination(dest)

	if data[0] != 2 {
		t.Fatalf("expected addrType 2 (domain), got %d", data[0])
	}
	domainLen := int(data[1])
	if domainLen != len("example.com") {
		t.Fatalf("expected domain length %d, got %d", len("example.com"), domainLen)
	}
	domain := string(data[2 : 2+domainLen])
	if domain != "example.com" {
		t.Fatalf("expected 'example.com', got %q", domain)
	}
	port := binary.BigEndian.Uint16(data[2+domainLen : 4+domainLen])
	if port != 80 {
		t.Fatalf("expected port 80, got %d", port)
	}
}

func TestMarshalDestinationRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		dest xnet.Destination
	}{
		{"IPv4", xnet.TCPDestination(xnet.IPAddress(net.ParseIP("10.0.0.1").To4()), 1234)},
		{"IPv6", xnet.TCPDestination(xnet.IPAddress(net.ParseIP("fe80::1").To16()), 5678)},
		{"Domain", xnet.TCPDestination(xnet.DomainAddress("test.example.org"), 9999)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := marshalDestination(tc.dest)
			if len(data) == 0 {
				t.Fatal("marshalled destination is empty")
			}

			// Verify the port is encoded at the end
			port := binary.BigEndian.Uint16(data[len(data)-2:])
			if xnet.Port(port) != tc.dest.Port {
				t.Fatalf("port mismatch: got %d, want %d", port, tc.dest.Port)
			}
		})
	}
}

func TestMarshalDestinationLongDomain(t *testing.T) {
	longDomain := "subdomain.of.a.very.long.domain.name.example.com"
	dest := xnet.TCPDestination(xnet.DomainAddress(longDomain), 443)
	data := marshalDestination(dest)

	if data[0] != 2 {
		t.Fatal("expected domain type")
	}
	if int(data[1]) != len(longDomain) {
		t.Fatalf("domain length mismatch: got %d, want %d", data[1], len(longDomain))
	}
}
