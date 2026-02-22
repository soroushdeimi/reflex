package encoding

import (
	"crypto/rand"
	"io"
	"testing"
)

// BenchmarkConnectionLifecycle100Frames simulates a connection with 100 frames
// to demonstrate allocation reduction from pooling
func BenchmarkConnectionLifecycle100Frames(b *testing.B) {
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		// Setup
		sessionKey := make([]byte, 32)
		io.ReadFull(rand.Reader, sessionKey)
		
		encoder, _ := NewFrameEncoder(sessionKey)
		decoder, _ := NewFrameDecoder(sessionKey)
		
		// Simulate 100 frames (typical for a connection)
		for frameNum := 0; frameNum < 100; frameNum++ {
			// Create a data frame with 4KB payload
			payload := make([]byte, 4096)
			io.ReadFull(rand.Reader, payload)
			
			frame := &Frame{
				Type:    FrameTypeData,
				Payload: payload,
			}
			
			// Encode frame (uses pooled buffers)
			encoded, _ := encoder.Encode(frame)
			
			// Decode frame (uses pooled buffers)
			decoded, _ := decoder.Decode(encoded)
			
			// Return buffers to pool
			PutFrame(decoded)
			PutFrameBuffer(encoded)
		}
	}
}

// BenchmarkHandshakeExchange simulates client-server handshake
func BenchmarkHandshakeExchange(b *testing.B) {
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		// Client handshake
		clientPrivateKey, clientPublicKey, _ := GenerateKeyPair()
		clientHS := &ClientHandshake{
			PublicKey: clientPublicKey,
			Timestamp: 1234567890,
		}
		
		// Encode client handshake (uses pooled buffer)
		clientData := EncodeClientHandshake(clientHS)
		
		// Decode client handshake
		decodedClient, _ := DecodeClientHandshake(clientData)
		
		// Server handshake
		_, serverPublicKey, _ := GenerateKeyPair()
		serverHS := &ServerHandshake{
			PublicKey: serverPublicKey,
			Timestamp: 1234567890,
		}

		// Encode server handshake (uses pooled buffer)
		serverData := EncodeServerHandshake(serverHS)

		// Decode server handshake
		decodedServer, _ := DecodeServerHandshake(serverData)

		// Derive keys
		sharedKey := DeriveSharedKey(clientPrivateKey, decodedServer.PublicKey)
		sessionKey, _ := DeriveSessionKey(sharedKey, []byte("test"))

		// Return buffers to pool
		PutClientHandshakeBuffer(clientData)
		PutServerHandshakeBuffer(serverData)

		_ = sessionKey
		_ = decodedClient
	}
}

// BenchmarkFramePoolEfficiency measures pool efficiency with concurrent access
func BenchmarkFramePoolEfficiency(b *testing.B) {
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			// Get and put in fast succession (measures reuse rate)
			buf := GetFrameBuffer(8192)
			PutFrameBuffer(buf)
			
			frame := GetFrame()
			PutFrame(frame)
		}
	})
}
