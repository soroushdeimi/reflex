package outbound

import (
	"bytes"
	"sync"
	"testing"

	"github.com/xtls/xray-core/proxy/reflex/encoding"
)

// TestConcurrentFrameEncodingDecoding tests concurrent encode/decode safely
func TestConcurrentFrameEncodingDecoding(t *testing.T) {
	sessionKey := make([]byte, 32)
	copy(sessionKey, "concurrent-test-key-32-bytes!!!")

	const numGoroutines = 10
	const framesPerGoroutine = 50

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines)

	decodedFrames := make([][]byte, 0)
	var decodeMu sync.Mutex

	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()

			encoder, err := encoding.NewFrameEncoder(sessionKey)
			if err != nil {
				errors <- err
				return
			}
			decoder, err := encoding.NewFrameDecoder(sessionKey)
			if err != nil {
				errors <- err
				return
			}

			for i := 0; i < framesPerGoroutine; i++ {
				payload := []byte("concurrent test data")
				frame := &encoding.Frame{
					Type:    encoding.FrameTypeData,
					Payload: payload,
				}

				encoded, err := encoder.Encode(frame)
				if err != nil {
					errors <- err
					return
				}

				decoded, err := decoder.Decode(encoded)
				if err != nil {
					errors <- err
					encoding.PutFrameBuffer(encoded)
					return
				}

				decodeMu.Lock()
				decodedFrames = append(decodedFrames, bytes.Clone(decoded.Payload))
				decodeMu.Unlock()

				encoding.PutFrame(decoded)
				encoding.PutFrameBuffer(encoded)
			}
		}(g)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		if err != nil {
			t.Errorf("concurrent operation failed: %v", err)
		}
	}

	expectedFrames := numGoroutines * framesPerGoroutine
	if len(decodedFrames) != expectedFrames {
		t.Errorf("expected %d decoded frames, got %d", expectedFrames, len(decodedFrames))
	}
}
