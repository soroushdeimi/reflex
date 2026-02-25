package tunnel

import (
	"bytes"
	"testing"

	xnet "github.com/xtls/xray-core/common/net"
)

func TestSocksAddrCodecIPv4(t *testing.T) {
	c := SocksAddrCodec{}
	dest := xnet.TCPDestination(xnet.IPAddress([]byte{1, 2, 3, 4}), xnet.Port(443))

	enc, err := c.Encode(dest)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	got, n, err := c.Decode(enc)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if n != len(enc) {
		t.Fatalf("headerLen: got %d want %d", n, len(enc))
	}
	assertDestEqual(t, got, dest)
}

func TestSocksAddrCodecDomain(t *testing.T) {
	c := SocksAddrCodec{}
	dest := xnet.TCPDestination(xnet.DomainAddress("example.com"), xnet.Port(80))

	enc, err := c.Encode(dest)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	got, n, err := c.Decode(enc)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if n != len(enc) {
		t.Fatalf("headerLen: got %d want %d", n, len(enc))
	}
	assertDestEqual(t, got, dest)
}

func TestSocksAddrCodecIPv6(t *testing.T) {
	c := SocksAddrCodec{}
	ip6 := []byte{
		0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 1,
	}
	dest := xnet.TCPDestination(xnet.IPAddress(ip6), xnet.Port(8443))

	enc, err := c.Encode(dest)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	got, n, err := c.Decode(enc)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if n != len(enc) {
		t.Fatalf("headerLen: got %d want %d", n, len(enc))
	}
	assertDestEqual(t, got, dest)
}

func TestSocksAddrCodecTruncated(t *testing.T) {
	c := SocksAddrCodec{}

	// IPv4 but truncated
	b := []byte{atypIPv4, 1, 2}
	if _, _, err := c.Decode(b); err == nil {
		t.Fatalf("expected error for truncated ipv4 header")
	}

	// Domain but truncated
	b = []byte{atypDomain, 10, 'a', 'b'}
	if _, _, err := c.Decode(b); err == nil {
		t.Fatalf("expected error for truncated domain header")
	}
}

func assertDestEqual(t *testing.T, got, want xnet.Destination) {
	t.Helper()

	if got.Network != want.Network {
		t.Fatalf("network: got %v want %v", got.Network, want.Network)
	}
	if got.Port != want.Port {
		t.Fatalf("port: got %v want %v", got.Port, want.Port)
	}
	if got.Address.Family() != want.Address.Family() {
		t.Fatalf("family: got %v want %v", got.Address.Family(), want.Address.Family())
	}

	switch got.Address.Family() {
	case xnet.AddressFamilyDomain:
		if got.Address.Domain() != want.Address.Domain() {
			t.Fatalf("domain: got %q want %q", got.Address.Domain(), want.Address.Domain())
		}
	case xnet.AddressFamilyIPv4, xnet.AddressFamilyIPv6:
		if !bytes.Equal(got.Address.IP(), want.Address.IP()) {
			t.Fatalf("ip: got %v want %v", got.Address.IP(), want.Address.IP())
		}
	default:
		t.Fatalf("unexpected family: %v", got.Address.Family())
	}
}
