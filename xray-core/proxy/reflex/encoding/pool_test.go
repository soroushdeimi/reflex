package encoding

import (
	"bytes"
	"sync"
	"testing"
)

// TestFrameBufferPoolGetPut tests basic get/put cycle for frame buffers
func TestFrameBufferPoolGetPut(t *testing.T) {
	// Test each pool tier
	sizes := []int{2048, 8192, 32768, 131072}

	for _, size := range sizes {
		buf := GetFrameBuffer(size)
		if len(buf) != size {
			t.Fatalf("GetFrameBuffer(%d): expected length %d, got %d", size, size, len(buf))
		}
		if cap(buf) < size {
			t.Fatalf("GetFrameBuffer(%d): capacity %d is less than size", size, cap(buf))
		}

		// Write some data
		for i := 0; i < size; i++ {
			buf[i] = byte(i % 256)
		}

		// Return to pool
		PutFrameBuffer(buf)

		// Get again - should reuse (data may be intact or cleared)
		buf2 := GetFrameBuffer(size)
		if len(buf2) != size {
			t.Fatalf("GetFrameBuffer(%d) after put: expected length %d, got %d", size, size, len(buf2))
		}

		PutFrameBuffer(buf2)
	}
}

// TestFrameBufferPoolSmallSize tests pooling with smaller than pool size
func TestFrameBufferPoolSmallSize(t *testing.T) {
	// Request 1KB, should come from 2KB pool
	buf := GetFrameBuffer(1024)
	if len(buf) != 1024 {
		t.Fatalf("GetFrameBuffer(1024): expected 1024, got %d", len(buf))
	}

	// Capacity should be at least 2048 (from first pool)
	if cap(buf) < 2048 {
		t.Fatalf("GetFrameBuffer(1024): expected capacity >= 2048, got %d", cap(buf))
	}

	PutFrameBuffer(buf)
}

// TestFrameBufferPoolOversized tests handling of oversized buffers
func TestFrameBufferPoolOversized(t *testing.T) {
	// Request size larger than largest pool (> 131KB)
	size := 256 * 1024 // 256KB
	buf := GetFrameBuffer(size)
	if len(buf) != size {
		t.Fatalf("GetFrameBuffer(%d): expected %d, got %d", size, size, len(buf))
	}

	// This goes to fallback allocation, not a pool
	PutFrameBuffer(buf) // Should be no-op for non-pooled buffers
}

// TestFrameStructPool tests Frame struct pooling
func TestFrameStructPool(t *testing.T) {
	// Get frame
	frame := GetFrame()
	if frame == nil {
		t.Fatal("GetFrame: returned nil")
	}

	// Set some data
	frame.Type = 1
	frame.Payload = []byte("test payload")

	// Return to pool
	PutFrame(frame)

	// Get another frame - should be cleared
	frame2 := GetFrame()
	if frame2 == nil {
		t.Fatal("GetFrame after put: returned nil")
	}
	if frame2.Type != 0 {
		t.Fatalf("GetFrame: Type not cleared, expected 0, got %d", frame2.Type)
	}
	if frame2.Payload != nil {
		t.Fatalf("GetFrame: Payload not cleared, expected nil, got %v", frame2.Payload)
	}

	PutFrame(frame2)
}

// TestHandshakeBufferPools tests client and server handshake buffer pools
func TestHandshakeBufferPools(t *testing.T) {
	// Test client handshake pool
	clientBuf := GetClientHandshakeBuffer()
	if len(clientBuf) != 76 {
		t.Fatalf("GetClientHandshakeBuffer: expected 76, got %d", len(clientBuf))
	}
	if cap(clientBuf) != 76 {
		t.Fatalf("GetClientHandshakeBuffer: expected capacity 76, got %d", cap(clientBuf))
	}

	// Write data
	for i := 0; i < 76; i++ {
		clientBuf[i] = byte(i)
	}

	// Return and get again
	PutClientHandshakeBuffer(clientBuf)
	clientBuf2 := GetClientHandshakeBuffer()
	if len(clientBuf2) != 76 {
		t.Fatalf("GetClientHandshakeBuffer after put: expected 76, got %d", len(clientBuf2))
	}
	PutClientHandshakeBuffer(clientBuf2)

	// Test server handshake pool
	serverBuf := GetServerHandshakeBuffer()
	if len(serverBuf) != 40 {
		t.Fatalf("GetServerHandshakeBuffer: expected 40, got %d", len(serverBuf))
	}
	if cap(serverBuf) != 40 {
		t.Fatalf("GetServerHandshakeBuffer: expected capacity 40, got %d", cap(serverBuf))
	}

	PutServerHandshakeBuffer(serverBuf)
	serverBuf2 := GetServerHandshakeBuffer()
	if len(serverBuf2) != 40 {
		t.Fatalf("GetServerHandshakeBuffer after put: expected 40, got %d", len(serverBuf2))
	}
	PutServerHandshakeBuffer(serverBuf2)
}

// TestPoolConcurrency tests concurrent pool access for thread safety
func TestPoolConcurrency(t *testing.T) {
	numGoroutines := 100
	operationsPerGoroutine := 10
	done := make(chan bool, numGoroutines)

	// Concurrent buffer pool operations
	for g := 0; g < numGoroutines; g++ {
		go func(id int) {
			for i := 0; i < operationsPerGoroutine; i++ {
				// Alternate between pool sizes
				size := []int{2048, 8192, 32768}[i%3]
				buf := GetFrameBuffer(size)
				if len(buf) != size {
					t.Errorf("Goroutine %d: size mismatch", id)
				}
				PutFrameBuffer(buf)
			}
			done <- true
		}(g)
	}

	// Wait for all goroutines
	for g := 0; g < numGoroutines; g++ {
		<-done
	}

	// Concurrent frame pool operations
	for g := 0; g < numGoroutines; g++ {
		go func(id int) {
			for i := 0; i < operationsPerGoroutine; i++ {
				frame := GetFrame()
				frame.Type = byte(id % 256)
				frame.Payload = []byte{byte(i)}
				PutFrame(frame)
			}
			done <- true
		}(g)
	}

	// Wait for all goroutines
	for g := 0; g < numGoroutines; g++ {
		<-done
	}

	// Concurrent handshake buffer operations
	for g := 0; g < numGoroutines; g++ {
		go func(id int) {
			for i := 0; i < operationsPerGoroutine; i++ {
				if i%2 == 0 {
					buf := GetClientHandshakeBuffer()
					PutClientHandshakeBuffer(buf)
				} else {
					buf := GetServerHandshakeBuffer()
					PutServerHandshakeBuffer(buf)
				}
			}
			done <- true
		}(g)
	}

	// Wait for all goroutines
	for g := 0; g < numGoroutines; g++ {
		<-done
	}
}

// TestPoolStatsFunction tests the PoolStats information function
func TestPoolStatsFunction(t *testing.T) {
	stats := GetPoolStats()

	expectedSizes := [numFramePools]int{2048, 8192, 32768, 131072}
	for i := 0; i < numFramePools; i++ {
		if stats.FrameBufferPoolSizes[i] != expectedSizes[i] {
			t.Fatalf("PoolStats: tier %d expected %d, got %d", i, expectedSizes[i], stats.FrameBufferPoolSizes[i])
		}
	}

	if stats.ClientHandshakeSize != 76 {
		t.Fatalf("PoolStats: ClientHandshakeSize expected 76, got %d", stats.ClientHandshakeSize)
	}

	if stats.ServerHandshakeSize != 40 {
		t.Fatalf("PoolStats: ServerHandshakeSize expected 40, got %d", stats.ServerHandshakeSize)
	}
}

// BenchmarkGetFrameBuffer benchmarks GetFrameBuffer performance
func BenchmarkGetFrameBuffer(b *testing.B) {
	sizes := []int{2048, 8192, 32768}

	for _, size := range sizes {
		b.Run(("Size"+string(rune(size))), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				buf := GetFrameBuffer(size)
				PutFrameBuffer(buf)
			}
		})
	}
}

// BenchmarkGetFrame benchmarks Frame struct pooling
func BenchmarkGetFrame(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		frame := GetFrame()
		frame.Type = byte(i % 256)
		PutFrame(frame)
	}
}

// BenchmarkGetHandshakeBuffer benchmarks handshake buffer pooling
func BenchmarkGetHandshakeBuffer(b *testing.B) {
	b.Run("Client", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			buf := GetClientHandshakeBuffer()
			PutClientHandshakeBuffer(buf)
		}
	})

	b.Run("Server", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			buf := GetServerHandshakeBuffer()
			PutServerHandshakeBuffer(buf)
		}
	})
}

// BenchmarkEncodeWithoutPooling benchmarks frame encoding without pooling (baseline)
func BenchmarkEncodeWithoutPooling(b *testing.B) {
	// Simulate encoding without pooling
	payload := []byte("hello world data for testing")
	nonce := make([]byte, 12)
	aead := testCreateAEAD()

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		// Simulate non-pooled allocation pattern
		plaintext := make([]byte, 1+len(payload))
		plaintext[0] = 1
		copy(plaintext[1:], payload)

		_ = aead.Seal(nil, nonce, plaintext, nil)
	}
}

// BenchmarkEncodeWithPooling benchmarks frame encoding with pooling
func BenchmarkEncodeWithPooling(b *testing.B) {
	// Simulate encoding with pooling
	payload := []byte("hello world data for testing")
	nonce := make([]byte, 12)
	aead := testCreateAEAD()

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		// Use pooled allocation
		plaintextSize := 1 + len(payload)
		plaintext := GetFrameBuffer(plaintextSize)
		plaintext[0] = 1
		copy(plaintext[1:], payload)

		_ = aead.Seal(nil, nonce, plaintext, nil)

		PutFrameBuffer(plaintext)
	}
}

// testCreateAEAD creates a test AEAD cipher for benchmarking
func testCreateAEAD() interface {
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
} {
	cipher, _ := NewFrameEncoder(make([]byte, 32))
	return cipher.aead
}

// TestPoolInvalidInputs tests pool functions with edge cases
func TestPoolInvalidInputs(t *testing.T) {
	// Test PutFrameBuffer with nil
	PutFrameBuffer(nil) // Should not panic

	// Test PutFrame with nil
	PutFrame(nil) // Should not panic

	// Test PutClientHandshakeBuffer with nil
	PutClientHandshakeBuffer(nil) // Should not panic

	// Test PutServerHandshakeBuffer with nil
	PutServerHandshakeBuffer(nil) // Should not panic

	// Test PutClientHandshakeBuffer with wrong size
	wrongSizedBuf := make([]byte, 50)
	PutClientHandshakeBuffer(wrongSizedBuf) // Should not be reused (size check fails)

	// Test PutServerHandshakeBuffer with wrong size
	wrongSizedBuf2 := make([]byte, 50)
	PutServerHandshakeBuffer(wrongSizedBuf2) // Should not be reused (size check fails)
}

// TestPoolBufferDataIntegrity tests that pool buffers maintain data correctly
func TestPoolBufferDataIntegrity(t *testing.T) {
	size := 8192
	buf := GetFrameBuffer(size)

	// Fill with pattern
	pattern := byte(0xAB)
	for i := 0; i < size; i++ {
		buf[i] = pattern
	}

	// Verify pattern
	for i := 0; i < size; i++ {
		if buf[i] != pattern {
			t.Fatalf("Buffer at index %d: expected %x, got %x", i, pattern, buf[i])
		}
	}

	PutFrameBuffer(buf)

	// Get new buffer - data may be different (pool may reuse without clearing)
	// but structure should be intact
	buf2 := GetFrameBuffer(size)
	if len(buf2) != size {
		t.Fatalf("Length after reuse: expected %d, got %d", size, len(buf2))
	}
	if cap(buf2) < size {
		t.Fatalf("Capacity after reuse: expected >= %d, got %d", size, cap(buf2))
	}

	PutFrameBuffer(buf2)
}

// TestPoolEmptyBuffer tests pooling empty/minimal buffers
func TestPoolEmptyBuffer(t *testing.T) {
	// Request 1 byte
	buf := GetFrameBuffer(1)
	if len(buf) != 1 {
		t.Fatalf("GetFrameBuffer(1): expected 1, got %d", len(buf))
	}
	buf[0] = 42
	PutFrameBuffer(buf)

	// Request 0 bytes (edge case)
	buf0 := GetFrameBuffer(0)
	if len(buf0) != 0 {
		t.Fatalf("GetFrameBuffer(0): expected 0, got %d", len(buf0))
	}
	PutFrameBuffer(buf0)
}

// TestFramePoolMultipleObjects tests pooling multiple Frame objects simultaneously
func TestFramePoolMultipleObjects(t *testing.T) {
	frames := make([]*Frame, 10)
	payloads := [][]byte{
		[]byte("frame1"),
		[]byte("frame2"),
		[]byte("frame3"),
		[]byte("frame4"),
		[]byte("frame5"),
		[]byte("frame6"),
		[]byte("frame7"),
		[]byte("frame8"),
		[]byte("frame9"),
		[]byte("frame10"),
	}

	// Get 10 frame objects
	for i := 0; i < 10; i++ {
		frames[i] = GetFrame()
		frames[i].Type = byte(i)
		frames[i].Payload = payloads[i]
	}

	// Verify data
	for i := 0; i < 10; i++ {
		if frames[i].Type != byte(i) {
			t.Fatalf("Frame %d: Type mismatch", i)
		}
		if !bytes.Equal(frames[i].Payload, payloads[i]) {
			t.Fatalf("Frame %d: Payload mismatch", i)
		}
	}

	// Return all frames
	for i := 0; i < 10; i++ {
		PutFrame(frames[i])
	}

	// Get them again (may be reused)
	frames2 := make([]*Frame, 10)
	for i := 0; i < 10; i++ {
		frames2[i] = GetFrame()
		if frames2[i].Type != 0 {
			t.Fatalf("Frame %d: Type not cleared", i)
		}
		if frames2[i].Payload != nil {
			t.Fatalf("Frame %d: Payload not cleared", i)
		}
	}

	// Return again
	for i := 0; i < 10; i++ {
		PutFrame(frames2[i])
	}
}

// TestPoolUnderStress tests pool under high-stress concurrent conditions
func TestPoolUnderStress(t *testing.T) {
	const (
		numWorkers     = 50
		operationsEach = 100
	)

	var wg sync.WaitGroup
	wg.Add(numWorkers)

	errChan := make(chan error, numWorkers)

	for worker := 0; worker < numWorkers; worker++ {
		go func(id int) {
			defer wg.Done()

			for op := 0; op < operationsEach; op++ {
				// Random mix of operations
				choice := (id + op) % 5

				switch choice {
				case 0:
					buf := GetFrameBuffer(2048)
					if len(buf) != 2048 {
						errChan <- newError("worker " + string(rune(id)) + " buffer size mismatch")
						return
					}
					PutFrameBuffer(buf)

				case 1:
					buf := GetFrameBuffer(8192)
					if len(buf) != 8192 {
						errChan <- newError("worker " + string(rune(id)) + " buffer size mismatch")
						return
					}
					PutFrameBuffer(buf)

				case 2:
					frame := GetFrame()
					frame.Type = byte(id)
					frame.Payload = []byte("test")
					PutFrame(frame)

				case 3:
					buf := GetClientHandshakeBuffer()
					if len(buf) != 76 {
						errChan <- newError("worker " + string(rune(id)) + " client handshake size mismatch")
						return
					}
					PutClientHandshakeBuffer(buf)

				case 4:
					buf := GetServerHandshakeBuffer()
					if len(buf) != 40 {
						errChan <- newError("worker " + string(rune(id)) + " server handshake size mismatch")
						return
					}
					PutServerHandshakeBuffer(buf)
				}
			}
		}(worker)
	}

	wg.Wait()
	close(errChan)

	// Check for errors
	for err := range errChan {
		if err != nil {
			t.Fatal(err)
		}
	}
}
