package inbound

import (
	"bytes"
	"crypto/rand"
	"testing"
	
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/reflex"
)

// BenchmarkKeyDerivation benchmarks X25519 key exchange and HKDF derivation
func BenchmarkKeyDerivation(b *testing.B) {
	clientPriv, clientPub, _ := generateKeyPair()
	serverPriv, serverPub, _ := generateKeyPair()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sharedClient := deriveSharedKey(clientPriv, serverPub)
		_ = deriveSessionKey(sharedClient, []byte("reflex-session"))
		
		sharedServer := deriveSharedKey(serverPriv, clientPub)
		_ = deriveSessionKey(sharedServer, []byte("reflex-session"))
	}
}

// BenchmarkEncryption benchmarks ChaCha20-Poly1305 encryption/decryption
func BenchmarkEncryption(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)
	session, _ := NewSession(key)
	
	data := make([]byte, 1024)
	rand.Read(data)
	
	b.ResetTimer()
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		_ = session.WriteFrame(&buf, FrameTypeData, data)
		_, _ = session.ReadFrame(&buf)
	}
}

// BenchmarkEncryptionSizes benchmarks encryption with different payload sizes
func BenchmarkEncryptionSizes(b *testing.B) {
	sizes := []int{64, 256, 1024, 4096, 16384}
	
	for _, size := range sizes {
		b.Run(string(rune(size)), func(b *testing.B) {
			key := make([]byte, 32)
			rand.Read(key)
			session, _ := NewSession(key)
			
			data := make([]byte, size)
			rand.Read(data)
			
			b.ResetTimer()
			b.ReportAllocs()
			b.SetBytes(int64(size))
			
			for i := 0; i < b.N; i++ {
				var buf bytes.Buffer
				_ = session.WriteFrame(&buf, FrameTypeData, data)
			}
		})
	}
}

// BenchmarkMorphing benchmarks traffic morphing (padding + delay calculation)
func BenchmarkMorphing(b *testing.B) {
	profile := DefaultProfiles["http2-api"]
	data := make([]byte, 512)
	rand.Read(data)
	
	b.ResetTimer()
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		_, _ = profile.ApplyMorphing(data)
	}
}

// BenchmarkHandshakeAuth benchmarks UUID authentication
func BenchmarkHandshakeAuth(b *testing.B) {
	u := uuid.New()
	config := &reflex.InboundConfig{
		Clients: []*reflex.User{
			{Id: u.String(), Policy: "http2-api"},
		},
	}
	h, _ := New(nil, config)
	handler := h.(*Handler)
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		_ = handler.authenticateUser(u)
	}
}

// BenchmarkFrameReadWrite benchmarks frame serialization
func BenchmarkFrameReadWrite(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)
	session, _ := NewSession(key)
	
	payload := []byte{2, 10, 'g', 'o', 'o', 'g', 'l', 'e', '.', 'c', 'o', 'm', 0x01, 0xBB}
	
	b.ResetTimer()
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		_ = session.WriteFrame(&buf, FrameTypeData, payload)
		_, _ = session.ReadFrame(&buf)
	}
}

// BenchmarkProfileSelection benchmarks traffic profile lookup
func BenchmarkProfileSelection(b *testing.B) {
	h := &Handler{}
	policies := []string{"http2-api", "youtube", "zoom", "unknown"}
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		for _, policy := range policies {
			_ = h.getProfile(policy)
		}
	}
}

// BenchmarkPacketSizeGeneration benchmarks weighted random packet size selection
func BenchmarkPacketSizeGeneration(b *testing.B) {
	profile := DefaultProfiles["youtube"]
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		_ = profile.GetPacketSize()
	}
}

// BenchmarkDelayGeneration benchmarks weighted random delay selection
func BenchmarkDelayGeneration(b *testing.B) {
	profile := DefaultProfiles["zoom"]
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		_ = profile.GetDelay()
	}
}

// BenchmarkX25519KeyGen benchmarks X25519 key pair generation
func BenchmarkX25519KeyGen(b *testing.B) {
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		_, _, _ = generateKeyPair()
	}
}

// BenchmarkMemoryAllocation measures memory allocations in encryption
func BenchmarkMemoryAllocation(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)
	session, _ := NewSession(key)
	data := make([]byte, 1024)
	rand.Read(data)
	
	b.ReportAllocs()
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		_ = session.WriteFrame(&buf, FrameTypeData, data)
	}
}
