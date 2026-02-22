package encoding

import (
	"sync"
)

// Tiered buffer pools for frame encoding/decoding optimization
// Follows the pattern from common/bytespool/pool.go

const (
	numFramePools = 4
	minPoolSize   = 2048  // 2KB
	poolSizeMulti = 4     // Each tier is 4x larger
)

var (
	// frameBufferPools holds sync.Pool instances for different buffer sizes
	frameBufferPools [numFramePools]sync.Pool

	// framePoolSizes defines the size of each tier
	framePoolSizes [numFramePools]int

	// framePool reuses Frame struct instances
	framePool = sync.Pool{
		New: func() interface{} {
			return &Frame{}
		},
	}

	// clientHandshakePool pools 76-byte buffers for client handshakes
	clientHandshakePool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 76) // CLIENT_HANDSHAKE_SIZE
		},
	}

	// serverHandshakePool pools 40-byte buffers for server handshakes
	serverHandshakePool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 40) // SERVER_HANDSHAKE_SIZE
		},
	}
)

func init() {
	// Initialize tiered buffer pools
	// Sizes: 2KB, 8KB, 32KB, 128KB
	// Covers typical frame sizes up to MaxFramePayloadSize + overhead
	size := minPoolSize
	for i := 0; i < numFramePools; i++ {
		framePoolSizes[i] = size

		// Capture size in closure for the New function
		poolSize := size
		frameBufferPools[i] = sync.Pool{
			New: func() interface{} {
				return make([]byte, poolSize)
			},
		}

		size *= poolSizeMulti
	}
}

// GetFrameBuffer retrieves a pooled buffer of at least size bytes.
// The returned buffer is sliced to the exact size requested.
// The caller must return it via PutFrameBuffer after use.
//
// For frames larger than 128KB, a new allocation is made (outside pools).
func GetFrameBuffer(size int) []byte {
	// Find the appropriate pool tier
	for i := 0; i < numFramePools; i++ {
		if size <= framePoolSizes[i] {
			buf := frameBufferPools[i].Get().([]byte)
			return buf[:size] // Slice to exact size needed
		}
	}

	// Fallback for oversized frames - allocate without pooling
	return make([]byte, size)
}

// PutFrameBuffer returns a buffer to the pool.
// The buffer is returned to the pool that matches its capacity.
// If capacity doesn't match any pool exactly, it's not reused.
func PutFrameBuffer(buf []byte) {
	if buf == nil {
		return
	}

	cap := cap(buf)

	// Find the pool that matches this capacity
	for i := numFramePools - 1; i >= 0; i-- {
		if cap >= framePoolSizes[i] {
			// Return to pool at full capacity
			frameBufferPools[i].Put(buf[:cap])
			return
		}
	}

	// Capacity smaller than smallest pool - don't reuse
}

// GetFrame retrieves a pooled Frame struct.
// The Frame should be returned via PutFrame after use.
func GetFrame() *Frame {
	return framePool.Get().(*Frame)
}

// PutFrame returns a Frame struct to the pool.
// The Frame must be cleared of sensitive data before returning.
func PutFrame(f *Frame) {
	if f == nil {
		return
	}

	// Clear sensitive payload reference and fields
	f.Payload = nil
	f.Type = 0

	framePool.Put(f)
}

// GetClientHandshakeBuffer retrieves a 76-byte buffer for client handshakes.
// The buffer should be returned via PutClientHandshakeBuffer after use.
func GetClientHandshakeBuffer() []byte {
	return clientHandshakePool.Get().([]byte)
}

// PutClientHandshakeBuffer returns a 76-byte buffer to the pool.
func PutClientHandshakeBuffer(buf []byte) {
	if buf != nil && cap(buf) == 76 {
		clientHandshakePool.Put(buf[:76])
	}
}

// GetServerHandshakeBuffer retrieves a 40-byte buffer for server handshakes.
// The buffer should be returned via PutServerHandshakeBuffer after use.
func GetServerHandshakeBuffer() []byte {
	return serverHandshakePool.Get().([]byte)
}

// PutServerHandshakeBuffer returns a 40-byte buffer to the pool.
func PutServerHandshakeBuffer(buf []byte) {
	if buf != nil && cap(buf) == 40 {
		serverHandshakePool.Put(buf[:40])
	}
}

// PoolStats provides information about pool usage (for testing/monitoring)
type PoolStats struct {
	FrameBufferPoolSizes [numFramePools]int
	ClientHandshakeSize  int
	ServerHandshakeSize  int
}

// GetPoolStats returns information about available pool tiers
func GetPoolStats() PoolStats {
	return PoolStats{
		FrameBufferPoolSizes: framePoolSizes,
		ClientHandshakeSize:  76,
		ServerHandshakeSize:  40,
	}
}
