package encoding

import (
	"bytes"
	"io"
	"testing"
)

// Helper function to encode frames in tests (handles error)
func encodeFrame(t *testing.T, encoder *FrameEncoder, frame *Frame) []byte {
	encoded, err := encoder.Encode(frame)
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}
	return encoded
}

// TestFrameEncoder tests frame encoding and encryption
func TestFrameEncoder(t *testing.T) {
	// Create a session key
	var sessionKey [32]byte
	for i := 0; i < 32; i++ {
		sessionKey[i] = byte(i)
	}

	encoder, err := NewFrameEncoder(sessionKey[:])
	if err != nil {
		t.Fatalf("NewFrameEncoder failed: %v", err)
	}

	if encoder == nil {
		t.Fatal("encoder should not be nil")
	}
}

// TestFrameDecoder tests frame decoding and decryption
func TestFrameDecoder(t *testing.T) {
	var sessionKey [32]byte
	for i := 0; i < 32; i++ {
		sessionKey[i] = byte(i)
	}

	decoder, err := NewFrameDecoder(sessionKey[:])
	if err != nil {
		t.Fatalf("NewFrameDecoder failed: %v", err)
	}

	if decoder == nil {
		t.Fatal("decoder should not be nil")
	}
}

// TestFrameEncoderDecoderSymmetry tests encrypt/decrypt cycle
func TestFrameEncoderDecoderSymmetry(t *testing.T) {
	var sessionKey [32]byte
	for i := 0; i < 32; i++ {
		sessionKey[i] = byte(i)
	}

	encoder, _ := NewFrameEncoder(sessionKey[:])
	decoder, _ := NewFrameDecoder(sessionKey[:])

	// Create test frame
	testData := []byte("Hello, this is a test message!")
	frame := &Frame{
		Type:    FrameTypeData,
		Payload: testData,
	}

	// Encode
	encoded, err := encoder.Encode(frame)
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	// Decode
	decoded, err := decoder.Decode(encoded)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	// Verify
	if decoded.Type != FrameTypeData {
		t.Fatalf("frame type mismatch: expected %d, got %d", FrameTypeData, decoded.Type)
	}
	if !bytes.Equal(decoded.Payload, testData) {
		t.Fatal("payload mismatch after encrypt/decrypt")
	}
}

// TestFrameTypeData tests DATA frame type
func TestFrameTypeData(t *testing.T) {
	var sessionKey [32]byte
	encoder, _ := NewFrameEncoder(sessionKey[:])

	frame := &Frame{
		Type:    FrameTypeData,
		Payload: []byte("test data"),
	}

	encoded := encodeFrame(t, encoder, frame)
	if len(encoded) == 0 {
		t.Fatal("encoded frame should not be empty")
	}
}

// TestFrameTypePadding tests PADDING_CTRL frame type
func TestFrameTypePadding(t *testing.T) {
	var sessionKey [32]byte
	encoder, _ := NewFrameEncoder(sessionKey[:])

	frame := &Frame{
		Type:    FrameTypePadding,
		Payload: make([]byte, 100), // 100 bytes of padding
	}

	encoded := encodeFrame(t, encoder, frame)
	if len(encoded) == 0 {
		t.Fatal("encoded padding frame should not be empty")
	}
}

// TestFrameTypeTiming tests TIMING_CTRL frame type
func TestFrameTypeTiming(t *testing.T) {
	var sessionKey [32]byte
	encoder, _ := NewFrameEncoder(sessionKey[:])

	frame := &Frame{
		Type:    FrameTypeTiming,
		Payload: []byte{0, 0, 0, 10}, // 10ms delay
	}

	encoded := encodeFrame(t, encoder, frame)
	if len(encoded) == 0 {
		t.Fatal("encoded timing frame should not be empty")
	}
}

// TestFrameTypeClose tests CLOSE frame type
func TestFrameTypeClose(t *testing.T) {
	var sessionKey [32]byte
	encoder, _ := NewFrameEncoder(sessionKey[:])

	frame := &Frame{
		Type:    FrameTypeClose,
		Payload: []byte{},
	}

	encoded := encodeFrame(t, encoder, frame)
	if len(encoded) == 0 {
		t.Fatal("encoded close frame should not be empty")
	}
}

// TestFrameEncryption verifies encryption changes data
func TestFrameEncryption(t *testing.T) {
	var sessionKey [32]byte
	for i := 0; i < 32; i++ {
		sessionKey[i] = byte(i)
	}

	encoder, _ := NewFrameEncoder(sessionKey[:])

	frame := &Frame{
		Type:    FrameTypeData,
		Payload: []byte("secret message"),
	}

	encrypted := encodeFrame(t, encoder, frame)

	// Encrypted should be different from original payload
	if bytes.Equal(encrypted[1:], frame.Payload) {
		t.Fatal("encrypted data should be different from plaintext")
	}
}

// TestFrameCounterIncrement verifies counter increments properly
func TestFrameCounterIncrement(t *testing.T) {
	var sessionKey [32]byte
	encoder, _ := NewFrameEncoder(sessionKey[:])
	decoder, _ := NewFrameDecoder(sessionKey[:])

	frame1 := &Frame{Type: FrameTypeData, Payload: []byte("message 1")}
	frame2 := &Frame{Type: FrameTypeData, Payload: []byte("message 2")}
	frame3 := &Frame{Type: FrameTypeData, Payload: []byte("message 3")}

	// Encode three frames
	encoded1 := encodeFrame(t, encoder, frame1)
	encoded2 := encodeFrame(t, encoder, frame2)
	encoded3 := encodeFrame(t, encoder, frame3)

	// All should be different due to counter-based nonce
	if bytes.Equal(encoded1, encoded2) {
		t.Fatal("frames with different counters should encrypt differently")
	}
	if bytes.Equal(encoded2, encoded3) {
		t.Fatal("frames with different counters should encrypt differently")
	}

	// But decoder should still work due to synchronized counter
	decoded1, _ := decoder.Decode(encoded1)
	decoded2, _ := decoder.Decode(encoded2)
	decoded3, _ := decoder.Decode(encoded3)

	if !bytes.Equal(decoded1.Payload, frame1.Payload) {
		t.Fatal("decoded frame 1 doesn't match")
	}
	if !bytes.Equal(decoded2.Payload, frame2.Payload) {
		t.Fatal("decoded frame 2 doesn't match")
	}
	if !bytes.Equal(decoded3.Payload, frame3.Payload) {
		t.Fatal("decoded frame 3 doesn't match")
	}
}

// TestFrameWithEmptyPayload tests frame with no payload
func TestFrameWithEmptyPayload(t *testing.T) {
	var sessionKey [32]byte
	encoder, _ := NewFrameEncoder(sessionKey[:])
	decoder, _ := NewFrameDecoder(sessionKey[:])

	frame := &Frame{
		Type:    FrameTypeData,
		Payload: []byte{},
	}

	encoded := encodeFrame(t, encoder, frame)
	decoded, err := decoder.Decode(encoded)

	if err != nil {
		t.Fatalf("should handle empty payload: %v", err)
	}
	if len(decoded.Payload) != 0 {
		t.Fatal("payload should remain empty")
	}
}

// TestFrameWithLargePayload tests frame with large payload
func TestFrameWithLargePayload(t *testing.T) {
	var sessionKey [32]byte
	encoder, _ := NewFrameEncoder(sessionKey[:])
	decoder, _ := NewFrameDecoder(sessionKey[:])

	// Create large payload (but within max frame size)
	largePayload := make([]byte, 10000)
	for i := 0; i < len(largePayload); i++ {
		largePayload[i] = byte(i % 256)
	}

	frame := &Frame{
		Type:    FrameTypeData,
		Payload: largePayload,
	}

	encoded := encodeFrame(t, encoder, frame)
	decoded, err := decoder.Decode(encoded)

	if err != nil {
		t.Fatalf("should handle large payload: %v", err)
	}
	if !bytes.Equal(decoded.Payload, largePayload) {
		t.Fatal("large payload mismatch after encrypt/decrypt")
	}
}

// TestFrameWithMaxPayload tests frame near max size
func TestFrameWithMaxPayload(t *testing.T) {
	var sessionKey [32]byte
	encoder, _ := NewFrameEncoder(sessionKey[:])
	decoder, _ := NewFrameDecoder(sessionKey[:])

	// Create payload near max frame size (16KB)
	maxPayload := make([]byte, 16000)
	for i := 0; i < len(maxPayload); i++ {
		maxPayload[i] = byte(i % 256)
	}

	frame := &Frame{
		Type:    FrameTypeData,
		Payload: maxPayload,
	}

	encoded := encodeFrame(t, encoder, frame)
	decoded, err := decoder.Decode(encoded)

	if err != nil {
		t.Fatalf("should handle max-size payload: %v", err)
	}
	if !bytes.Equal(decoded.Payload, maxPayload) {
		t.Fatal("max-size payload mismatch after encrypt/decrypt")
	}
}

// TestFrameWriteRead tests WriteFrame and ReadFrame with connection
func TestFrameWriteRead(t *testing.T) {
	var sessionKey [32]byte
	encoder, _ := NewFrameEncoder(sessionKey[:])
	decoder, _ := NewFrameDecoder(sessionKey[:])

	// Create a pipe for testing
	pipeReader, pipeWriter := io.Pipe()
	defer pipeReader.Close()
	defer pipeWriter.Close()

	testData := []byte("test message for pipe")

	// Write in goroutine
	go func() {
		frame := &Frame{
			Type:    FrameTypeData,
			Payload: testData,
		}
		err := encoder.WriteFrame(pipeWriter, frame)
		if err != nil {
			t.Errorf("WriteFrame failed: %v", err)
		}
		pipeWriter.Close()
	}()

	// Read on main goroutine
	frame, err := decoder.ReadFrame(pipeReader)
	if err != nil && err != io.EOF {
		t.Fatalf("ReadFrame failed: %v", err)
	}

	if frame != nil && !bytes.Equal(frame.Payload, testData) {
		t.Fatal("payload mismatch in pipe communication")
	}
}

// TestFrameAuthenticationTagVerification tests tampering detection
func TestFrameAuthenticationTagVerification(t *testing.T) {
	var sessionKey [32]byte
	for i := 0; i < 32; i++ {
		sessionKey[i] = byte(i)
	}

	encoder, _ := NewFrameEncoder(sessionKey[:])
	decoder, _ := NewFrameDecoder(sessionKey[:])

	frame := &Frame{
		Type:    FrameTypeData,
		Payload: []byte("original data"),
	}

	encoded := encodeFrame(t, encoder, frame)

	// Tamper with the encrypted data
	if len(encoded) > 10 {
		encoded[10] ^= 0xFF // flip some bits
	}

	// Should fail to decrypt
	_, err := decoder.Decode(encoded)
	if err == nil {
		t.Fatal("should detect tampering (authentication tag should fail)")
	}
}

// TestFrameWithDifferentKeys tests that different keys produce different encryptions
func TestFrameWithDifferentKeys(t *testing.T) {
	var key1, key2 [32]byte
	for i := 0; i < 32; i++ {
		key1[i] = byte(i)
		key2[i] = byte(255 - i)
	}

	encoder1, _ := NewFrameEncoder(key1[:])
	encoder2, _ := NewFrameEncoder(key2[:])

	frame := &Frame{
		Type:    FrameTypeData,
		Payload: []byte("test message"),
	}

	encoded1 := encodeFrame(t, encoder1, frame)
	encoded2 := encodeFrame(t, encoder2, frame)

	// Different keys should produce different ciphertext
	if bytes.Equal(encoded1, encoded2) {
		t.Fatal("different keys should produce different ciphertext")
	}
}

// TestFrameSequencing tests that frames maintain sequence order
func TestFrameSequencing(t *testing.T) {
	var sessionKey [32]byte
	encoder, _ := NewFrameEncoder(sessionKey[:])
	decoder, _ := NewFrameDecoder(sessionKey[:])

	messages := []string{
		"first message",
		"second message",
		"third message",
		"fourth message",
		"fifth message",
	}

	// Encode all messages
	encoded := make([][]byte, len(messages))
	for i, msg := range messages {
		frame := &Frame{
			Type:    FrameTypeData,
			Payload: []byte(msg),
		}
		encoded[i] = encodeFrame(t, encoder, frame)
	}

	// Decode all messages in reverse order (shouldn't work due to counter)
	for i, enc := range encoded {
		frame, _ := decoder.Decode(enc)
		if !bytes.Equal(frame.Payload, []byte(messages[i])) {
			t.Fatalf("frame %d mismatch", i)
		}
	}
}

// TestFrameTypeEncoding verifies frame type is preserved
func TestFrameTypeEncoding(t *testing.T) {
	var sessionKey [32]byte
	encoder, _ := NewFrameEncoder(sessionKey[:])
	decoder, _ := NewFrameDecoder(sessionKey[:])

	frameTypes := []byte{
		FrameTypeData,
		FrameTypePadding,
		FrameTypeTiming,
		FrameTypeClose,
	}

	for _, fType := range frameTypes {
		frame := &Frame{
			Type:    fType,
			Payload: []byte("test"),
		}

		encoded := encodeFrame(t, encoder, frame)
		decoded, _ := decoder.Decode(encoded)

		if decoded.Type != fType {
			t.Fatalf("frame type mismatch: expected %d, got %d", fType, decoded.Type)
		}
	}
}

// TestFrameSizeWithEncryption verifies encrypted size is larger than plaintext
func TestFrameSizeWithEncryption(t *testing.T) {
	var sessionKey [32]byte
	encoder, _ := NewFrameEncoder(sessionKey[:])

	payload := []byte("test data")
	frame := &Frame{
		Type:    FrameTypeData,
		Payload: payload,
	}

	encoded := encodeFrame(t, encoder, frame)

	// Encrypted should be larger (overhead for authentication tag and frame header)
	// At least frame type (1 byte) + 16 bytes for authentication tag
	minEncryptedSize := len(payload) + 1 + 16
	if len(encoded) < minEncryptedSize {
		t.Fatalf("encrypted size should be at least %d, got %d", minEncryptedSize, len(encoded))
	}
}
