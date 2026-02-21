package inbound

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"

	xnet "github.com/xtls/xray-core/common/net"
)

func TestParseDestinationIPv4(t *testing.T) {
	// Format: [addrType=1][IPv4 4 bytes][port 2 bytes][remaining payload]
	var data []byte
	data = append(data, 1) // IPv4
	data = append(data, 127, 0, 0, 1)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, 8080)
	data = append(data, portBytes...)
	data = append(data, []byte("extra payload")...)

	dest, remaining, err := parseDestination(data)
	if err != nil {
		t.Fatalf("parseDestination IPv4 failed: %v", err)
	}

	if dest.Address.String() != "127.0.0.1" {
		t.Fatalf("expected address 127.0.0.1, got %s", dest.Address.String())
	}
	if dest.Port != 8080 {
		t.Fatalf("expected port 8080, got %d", dest.Port)
	}
	if string(remaining) != "extra payload" {
		t.Fatalf("unexpected remaining: %q", remaining)
	}
}

func TestParseDestinationDomain(t *testing.T) {
	// Format: [addrType=2][domainLen 1 byte][domain][port 2 bytes]
	domain := "example.com"
	var data []byte
	data = append(data, 2) // Domain
	data = append(data, byte(len(domain)))
	data = append(data, []byte(domain)...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, 443)
	data = append(data, portBytes...)

	dest, remaining, err := parseDestination(data)
	if err != nil {
		t.Fatalf("parseDestination domain failed: %v", err)
	}

	if dest.Address.String() != "example.com" {
		t.Fatalf("expected example.com, got %s", dest.Address.String())
	}
	if dest.Port != 443 {
		t.Fatalf("expected port 443, got %d", dest.Port)
	}
	if len(remaining) != 0 {
		t.Fatalf("expected no remaining data, got %d bytes", len(remaining))
	}
}

func TestParseDestinationIPv6(t *testing.T) {
	// Format: [addrType=3][IPv6 16 bytes][port 2 bytes]
	var data []byte
	data = append(data, 3) // IPv6
	ipv6 := net.ParseIP("::1").To16()
	data = append(data, ipv6...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, 80)
	data = append(data, portBytes...)
	data = append(data, []byte("rest")...)

	dest, remaining, err := parseDestination(data)
	if err != nil {
		t.Fatalf("parseDestination IPv6 failed: %v", err)
	}

	if dest.Port != 80 {
		t.Fatalf("expected port 80, got %d", dest.Port)
	}
	if string(remaining) != "rest" {
		t.Fatalf("unexpected remaining: %q", remaining)
	}
	_ = dest.Address
}

func TestParseDestinationTooShort(t *testing.T) {
	_, _, err := parseDestination([]byte{0x01, 0x02})
	if err == nil {
		t.Fatal("expected error for too-short data")
	}
}

func TestParseDestinationUnsupportedType(t *testing.T) {
	data := []byte{0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	_, _, err := parseDestination(data)
	if err == nil {
		t.Fatal("expected error for unsupported address type")
	}
}

func TestParseDestinationIPv4TooShort(t *testing.T) {
	// addrType=1 but not enough bytes for IPv4 + port
	data := []byte{1, 127, 0, 0}
	_, _, err := parseDestination(data)
	if err == nil {
		t.Fatal("expected error for truncated IPv4")
	}
}

func TestParseDestinationDomainTooShort(t *testing.T) {
	// addrType=2, domainLen=20, but not enough bytes
	data := []byte{2, 20, 'a', 'b', 'c'}
	_, _, err := parseDestination(data)
	if err == nil {
		t.Fatal("expected error for truncated domain")
	}
}

func TestParseDestinationDomainLengthOnly(t *testing.T) {
	// addrType=2 but only 1 byte (just the type)
	data := []byte{2}
	_, _, err := parseDestination(data)
	if err == nil {
		t.Fatal("expected error for missing domain length")
	}
}

func TestParseDestinationIPv6TooShort(t *testing.T) {
	// addrType=3 but not enough bytes for IPv6 + port
	data := make([]byte, 10)
	data[0] = 3
	_, _, err := parseDestination(data)
	if err == nil {
		t.Fatal("expected error for truncated IPv6")
	}
}

func TestHandlerNetwork(t *testing.T) {
	h := &Handler{}
	nets := h.Network()
	if len(nets) != 1 {
		t.Fatalf("expected 1 network, got %d", len(nets))
	}
	if nets[0] != xnet.Network_TCP {
		t.Fatalf("expected TCP, got %v", nets[0])
	}
}

func TestPreloadedConnRead(t *testing.T) {
	data := []byte("hello preloaded world")
	reader := bufio.NewReader(bytes.NewReader(data))

	// Peek first to simulate inbound behaviour
	peeked, err := reader.Peek(5)
	if err != nil {
		t.Fatal(err)
	}
	if string(peeked) != "hello" {
		t.Fatalf("peeked: %q", peeked)
	}

	// Create a mock connection using net.Pipe for the embedded Connection
	clientConn, _ := net.Pipe()
	defer func() { _ = clientConn.Close() }()

	// Use io.Reader interface from preloadedConn
	pc := &preloadedConn{reader: reader}

	buf := make([]byte, 100)
	n, err := pc.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if string(buf[:n]) != "hello preloaded world" {
		t.Fatalf("expected full data, got %q", buf[:n])
	}
}
