package encoding

import (
	"github.com/xtls/xray-core/common/buf"
)

// BufferManager handles efficient buffer pooling and frame batching
type BufferManager struct {
	readBuffer  buf.MultiBuffer
	writeBuffer buf.MultiBuffer
	maxFrameSize int
}

// NewBufferManager creates a new buffer manager
func NewBufferManager() *BufferManager {
	return &BufferManager{
		maxFrameSize: MaxFramePayloadSize,
	}
}

// BatchFrames batches small writes into larger frames for efficiency
func (bm *BufferManager) BatchFrames(mb buf.MultiBuffer) [][]byte {
	var batches [][]byte
	currentBatch := make([]byte, 0, bm.maxFrameSize)

	for _, b := range mb {
		data := b.Bytes()

		// If adding this buffer would exceed max frame size, start a new batch
		if len(currentBatch)+len(data) > bm.maxFrameSize {
			if len(currentBatch) > 0 {
				// Save current batch
				batches = append(batches, currentBatch)
				currentBatch = make([]byte, 0, bm.maxFrameSize)
			}

			// If this single buffer is larger than max frame size, split it
			if len(data) > bm.maxFrameSize {
				for i := 0; i < len(data); i += bm.maxFrameSize {
					end := i + bm.maxFrameSize
					if end > len(data) {
						end = len(data)
					}
					batches = append(batches, data[i:end])
				}
				continue
			}
		}

		// Add to current batch
		currentBatch = append(currentBatch, data...)
	}

	// Add remaining batch
	if len(currentBatch) > 0 {
		batches = append(batches, currentBatch)
	}

	return batches
}

// Release releases all buffers
func (bm *BufferManager) Release() {
	buf.ReleaseMulti(bm.readBuffer)
	buf.ReleaseMulti(bm.writeBuffer)
	bm.readBuffer = nil
	bm.writeBuffer = nil
}
