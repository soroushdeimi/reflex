package inbound

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"math/big"
	stdnet "net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func generateTestCert() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []stdnet.IP{stdnet.ParseIP("127.0.0.1")},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	return tls.X509KeyPair(certPEM, keyPEM)
}

func TestTLSIntegration(t *testing.T) {
	cert, err := generateTestCert()
	if err != nil {
		t.Fatal(err)
	}

	config := &reflex.InboundConfig{
		UseTls: true,
		Clients: []*reflex.User{
			{Id: "00000000-0000-0000-0000-000000000001"},
		},
	}

	ctx := context.Background()
	h, err := New(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	handler := h.(*Handler)
	handler.tlsConfig.Certificates = []tls.Certificate{cert}

	// Mock dispatcher
	// In a real test, we would use a real dispatcher or mock it.

	listener, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	addr := listener.Addr().String()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		// In Xray, we should pass something that implements stat.Connection
		handler.Process(ctx, net.Network_TCP, conn.(stat.Connection), nil)
	}()

	// Client
	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Send Reflex Handshake
	writer := bufio.NewWriter(conn)
	// Magic
	_ = binary.Write(writer, binary.BigEndian, uint32(0x52454658)) // REFX
	// PK
	_, _ = conn.Write(make([]byte, 32))
	// UUID
	id, _ := uuid.ParseString("00000000-0000-0000-0000-000000000001")
	_, _ = conn.Write(id[:])
	// Timestamp
	_ = binary.Write(writer, binary.BigEndian, uint64(time.Now().Unix()))
	// Nonce
	_, _ = conn.Write(make([]byte, 16))
	writer.Flush()

	// The server should process this.
	// Since we passed nil dispatcher, it might fail later, but the handshake should pass.
}

func TestQUICIntegration(t *testing.T) {
	cert, err := generateTestCert()
	if err != nil {
		t.Fatal(err)
	}

	config := &reflex.InboundConfig{
		UseTls:  true,
		UseQuic: true,
		Clients: []*reflex.User{
			{Id: "00000000-0000-0000-0000-000000000001"},
		},
	}

	ctx := context.Background()
	h, err := New(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	handler := h.(*Handler)
	handler.tlsConfig.Certificates = []tls.Certificate{cert}
	handler.tlsConfig.NextProtos = []string{"h3", "reflex"}

	addr := "127.0.0.1:18888" // Use a fixed port for test simplicity or find one

	// Start QUIC
	err = handler.StartQUIC(addr, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Client
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3", "reflex"},
	}
	conn, err := quic.DialAddr(ctx, addr, tlsConfig, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()

	// Send Reflex Handshake
	writer := bufio.NewWriter(stream)
	_ = binary.Write(writer, binary.BigEndian, uint32(0x52454658)) // REFX
	_, _ = stream.Write(make([]byte, 32))                          // PK
	id, _ := uuid.ParseString("00000000-0000-0000-0000-000000000001")
	_, _ = stream.Write(id[:])
	_ = binary.Write(writer, binary.BigEndian, uint64(time.Now().Unix()))
	_, _ = stream.Write(make([]byte, 16)) // Nonce
	writer.Flush()
}
