package inbound

import (
	"bytes"
	"crypto/rand"
	"strconv"
	"testing"

	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/reflex"
)

func BenchmarkKeyDerivation(b *testing.B) {
	p1, pub1, _ := generateKeyPair()
	p2, pub2, _ := generateKeyPair()
	label := []byte("reflex-session")

	b.ResetTimer()
	for k := 0; k < b.N; k++ {
		s1 := deriveSharedKey(p1, pub2)
		_ = deriveSessionKey(s1, label)

		s2 := deriveSharedKey(p2, pub1)
		_ = deriveSessionKey(s2, label)
	}
}

func BenchmarkEncryption(b *testing.B) {
	kBuf := make([]byte, 32)
	rand.Read(kBuf)
	sess, _ := NewSession(kBuf)

	chunk := make([]byte, 1024)
	rand.Read(chunk)

	b.ReportAllocs()
	b.ResetTimer()

	for k := 0; k < b.N; k++ {
		var tmp bytes.Buffer
		_ = sess.WriteFrame(&tmp, FrameTypeData, chunk)
		_, _ = sess.ReadFrame(&tmp)
	}
}

func BenchmarkEncryptionSizes(b *testing.B) {
	for _, sz := range []int{64, 256, 1024, 4096, 16384} {
		b.Run(strconv.Itoa(sz), func(bb *testing.B) {
			kBuf := make([]byte, 32)
			rand.Read(kBuf)
			sess, _ := NewSession(kBuf)

			chunk := make([]byte, sz)
			rand.Read(chunk)

			bb.SetBytes(int64(sz))
			bb.ReportAllocs()
			bb.ResetTimer()

			for k := 0; k < bb.N; k++ {
				var tmp bytes.Buffer
				_ = sess.WriteFrame(&tmp, FrameTypeData, chunk)
			}
		})
	}
}

func BenchmarkMorphing(b *testing.B) {
	prof := DefaultProfiles["http2-api"]
	chunk := make([]byte, 512)
	rand.Read(chunk)

	b.ReportAllocs()
	b.ResetTimer()

	for k := 0; k < b.N; k++ {
		_, _ = prof.ApplyMorphing(chunk)
	}
}

func BenchmarkHandshakeAuth(b *testing.B) {
	uid := uuid.New()
	cfg := &reflex.InboundConfig{
		Clients: []*reflex.User{{Id: uid.String(), Policy: "http2-api"}},
	}
	raw, _ := New(nil, cfg)
	inst := raw.(*Handler)

	b.ResetTimer()
	for k := 0; k < b.N; k++ {
		_ = inst.authenticateUser(uid)
	}
}

func BenchmarkFrameReadWrite(b *testing.B) {
	kBuf := make([]byte, 32)
	rand.Read(kBuf)
	sess, _ := NewSession(kBuf)

	pld := []byte{2, 10, 'g', 'o', 'o', 'g', 'l', 'e', '.', 'c', 'o', 'm', 0x01, 0xBB}

	b.ReportAllocs()
	b.ResetTimer()

	for k := 0; k < b.N; k++ {
		var tmp bytes.Buffer
		_ = sess.WriteFrame(&tmp, FrameTypeData, pld)
		_, _ = sess.ReadFrame(&tmp)
	}
}

func BenchmarkProfileSelection(b *testing.B) {
	inst := &Handler{}
	keys := []string{"http2-api", "youtube", "zoom", "unknown"}

	b.ResetTimer()
	for k := 0; k < b.N; k++ {
		for _, key := range keys {
			_ = inst.getProfile(key)
		}
	}
}

func BenchmarkPacketSizeGeneration(b *testing.B) {
	prof := DefaultProfiles["youtube"]
	b.ResetTimer()
	for k := 0; k < b.N; k++ {
		_ = prof.GetPacketSize()
	}
}

func BenchmarkDelayGeneration(b *testing.B) {
	prof := DefaultProfiles["zoom"]
	b.ResetTimer()
	for k := 0; k < b.N; k++ {
		_ = prof.GetDelay()
	}
}

func BenchmarkX25519KeyGen(b *testing.B) {
	b.ResetTimer()
	for k := 0; k < b.N; k++ {
		_, _, _ = generateKeyPair()
	}
}

func BenchmarkMemoryAllocation(b *testing.B) {
	kBuf := make([]byte, 32)
	rand.Read(kBuf)
	sess, _ := NewSession(kBuf)
	chunk := make([]byte, 1024)
	rand.Read(chunk)

	b.ReportAllocs()
	b.ResetTimer()

	for k := 0; k < b.N; k++ {
		var tmp bytes.Buffer
		_ = sess.WriteFrame(&tmp, FrameTypeData, chunk)
	}
}