package benchmarks

import (
	"bytes"
	"context"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/reflex/inbound"
	"github.com/xtls/xray-core/proxy/trojan"
	vless "github.com/xtls/xray-core/proxy/vless"
	vlessenc "github.com/xtls/xray-core/proxy/vless/encoding"
	vmess "github.com/xtls/xray-core/proxy/vmess"
	vmessenc "github.com/xtls/xray-core/proxy/vmess/encoding"
)

func BenchmarkProtocolRequestWithPayload1KB(b *testing.B) {
	payload := bytes.Repeat([]byte("x"), 1024)

	b.Run("Reflex", func(b *testing.B) {
		session, err := inbound.NewSession(bytes.Repeat([]byte{1}, 32))
		if err != nil {
			b.Fatalf("new reflex session: %v", err)
		}

		var out bytes.Buffer
		b.ReportAllocs()
		b.SetBytes(int64(len(payload)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			out.Reset()
			if err := session.WriteFrame(&out, inbound.FrameTypeData, payload); err != nil {
				b.Fatalf("reflex write frame: %v", err)
			}
		}
	})

	b.Run("VLESS", func(b *testing.B) {
		vlessAccount, err := (&vless.Account{Id: "123e4567-e89b-12d3-a456-426614174000", Encryption: "none"}).AsAccount()
		if err != nil {
			b.Fatalf("new vless account: %v", err)
		}
		addons := &vlessenc.Addons{}

		req := &protocol.RequestHeader{
			Version:  vlessenc.Version,
			User:     &protocol.MemoryUser{Account: vlessAccount},
			Command:  protocol.RequestCommandTCP,
			Address:  xnet.DomainAddress("example.com"),
			Port:     xnet.Port(443),
			Security: protocol.SecurityType_NONE,
		}

		var out bytes.Buffer
		b.ReportAllocs()
		b.SetBytes(int64(len(payload)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			out.Reset()
			if err := vlessenc.EncodeRequestHeader(&out, req, addons); err != nil {
				b.Fatalf("vless encode header: %v", err)
			}
			if _, err := out.Write(payload); err != nil {
				b.Fatalf("vless write payload: %v", err)
			}
		}
	})

	b.Run("VMess", func(b *testing.B) {
		vmessAccount, err := (&vmess.Account{Id: "123e4567-e89b-12d3-a456-426614174001"}).AsAccount()
		if err != nil {
			b.Fatalf("new vmess account: %v", err)
		}

		req := &protocol.RequestHeader{
			Version:  vmessenc.Version,
			User:     &protocol.MemoryUser{Account: vmessAccount},
			Command:  protocol.RequestCommandTCP,
			Address:  xnet.DomainAddress("example.com"),
			Port:     xnet.Port(443),
			Security: protocol.SecurityType_CHACHA20_POLY1305,
		}

		var out bytes.Buffer
		b.ReportAllocs()
		b.SetBytes(int64(len(payload)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			out.Reset()
			s := vmessenc.NewClientSession(context.Background(), 0)
			if err := s.EncodeRequestHeader(req, &out); err != nil {
				b.Fatalf("vmess encode header: %v", err)
			}
			w, err := s.EncodeRequestBody(req, &out)
			if err != nil {
				b.Fatalf("vmess encode body writer: %v", err)
			}
			if err := w.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(payload)}); err != nil {
				b.Fatalf("vmess write body: %v", err)
			}
		}
	})

	b.Run("Trojan", func(b *testing.B) {
		trojanAccount, err := (&trojan.Account{Password: "benchmark-pass"}).AsAccount()
		if err != nil {
			b.Fatalf("new trojan account: %v", err)
		}

		trojanMem := trojanAccount.(*trojan.MemoryAccount)
		target := xnet.TCPDestination(xnet.DomainAddress("example.com"), xnet.Port(443))

		var out bytes.Buffer
		b.ReportAllocs()
		b.SetBytes(int64(len(payload)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			out.Reset()
			w := &trojan.ConnWriter{
				Writer:  &out,
				Target:  target,
				Account: trojanMem,
			}
			if _, err := w.Write(payload); err != nil {
				b.Fatalf("trojan write: %v", err)
			}
		}
	})
}
