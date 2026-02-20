package reflex

import (
	"bytes"
	"testing"

	xnet "github.com/xtls/xray-core/common/net"
)

func TestEncodeDecodeDestination_IPv4(t *testing.T) {
	dest := xnet.TCPDestination(
		xnet.ParseAddress("1.2.3.4"),
		xnet.Port(443),
	)

	encoded := EncodeDestination(dest)

	decoded, err := DecodeDestination(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}

	if decoded.Address.String() != dest.Address.String() {
		t.Fatalf("address mismatch: %s != %s",
			decoded.Address.String(), dest.Address.String())
	}

	if decoded.Port != dest.Port {
		t.Fatalf("port mismatch: %d != %d",
			decoded.Port, dest.Port)
	}
}

func TestEncodeDecodeDestination_IPv6(t *testing.T) {
	dest := xnet.TCPDestination(
		xnet.ParseAddress("2001:db8::1"),
		xnet.Port(8443),
	)

	encoded := EncodeDestination(dest)

	decoded, err := DecodeDestination(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}

	if decoded.Address.String() != dest.Address.String() {
		t.Fatalf("address mismatch: %s != %s",
			decoded.Address.String(), dest.Address.String())
	}

	if decoded.Port != dest.Port {
		t.Fatalf("port mismatch: %d != %d",
			decoded.Port, dest.Port)
	}
}

func TestEncodeDecodeDestination_Domain(t *testing.T) {
	dest := xnet.TCPDestination(
		xnet.ParseAddress("example.com"),
		xnet.Port(80),
	)

	encoded := EncodeDestination(dest)

	decoded, err := DecodeDestination(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}

	if decoded.Address.String() != dest.Address.String() {
		t.Fatalf("address mismatch: %s != %s",
			decoded.Address.String(), dest.Address.String())
	}

	if decoded.Port != dest.Port {
		t.Fatalf("port mismatch: %d != %d",
			decoded.Port, dest.Port)
	}
}

func TestDecodeDestination_InvalidType(t *testing.T) {
	// invalid address type = 9
	data := []byte{9, 4, 1, 2, 3, 4, 0, 80}

	_, err := DecodeDestination(bytes.NewReader(data))
	if err == nil {
		t.Fatal("expected error for invalid address type")
	}
}

func TestDecodeDestination_Truncated(t *testing.T) {
	// incomplete data
	data := []byte{1, 4, 1}

	_, err := DecodeDestination(bytes.NewReader(data))
	if err == nil {
		t.Fatal("expected error for truncated input")
	}
}
