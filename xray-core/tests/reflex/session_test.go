package reflex_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/xtls/xray-core/proxy/reflex"
)

var testSessionKey = make([]byte, 32)

func init() {
	rand.Read(testSessionKey)
}

func TestNewSession(t *testing.T) {
	session, err := reflex.NewSession(testSessionKey)
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}

	if session == nil {
		t.Fatal("session is nil")
	}

	if session.GetMorphingConfig() == nil {
		t.Error("morphing config should not be nil")
	}
}

func TestNewSessionInvalidKey(t *testing.T) {
	shortKey := make([]byte, 16)
	_, err := reflex.NewSession(shortKey)
	if err == nil {
		t.Fatal("should reject invalid key length")
	}
}

func TestWriteReadFrame(t *testing.T) {
	session, _ := reflex.NewSession(testSessionKey)
	buf := &bytes.Buffer{}

	original := []byte("test data")
	err := session.WriteFrame(buf, reflex.FrameTypeData, original)
	if err != nil {
		t.Fatalf("WriteFrame failed: %v", err)
	}

	frame, err := session.ReadFrame(buf)
	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}

	if frame.Type != reflex.FrameTypeData {
		t.Errorf("frame type mismatch: got %d, want %d", frame.Type, reflex.FrameTypeData)
	}

	// Note: payload may be morphed (padded), so we check if original is prefix
	if !bytes.HasPrefix(frame.Payload, original) {
		t.Error("payload mismatch")
	}
}

func TestWriteReadFrameMultiple(t *testing.T) {
	session, _ := reflex.NewSession(testSessionKey)
	buf := &bytes.Buffer{}

	testData := [][]byte{
		[]byte("data1"),
		[]byte("data2"),
		[]byte("data3"),
	}

	for _, data := range testData {
		if err := session.WriteFrame(buf, reflex.FrameTypeData, data); err != nil {
			t.Fatalf("WriteFrame failed: %v", err)
		}
	}

	for i, expected := range testData {
		frame, err := session.ReadFrame(buf)
		if err != nil {
			t.Fatalf("ReadFrame %d failed: %v", i, err)
		}
		if !bytes.HasPrefix(frame.Payload, expected) {
			t.Errorf("frame %d payload mismatch", i)
		}
	}
}

func TestFrameTypes(t *testing.T) {
	session, _ := reflex.NewSession(testSessionKey)
	buf := &bytes.Buffer{}

	frameTypes := []uint8{reflex.FrameTypeData, reflex.FrameTypePadding, reflex.FrameTypeTiming, reflex.FrameTypeClose}
	for _, frameType := range frameTypes {
		buf.Reset()
		data := []byte("test")
		if err := session.WriteFrame(buf, frameType, data); err != nil {
			t.Errorf("WriteFrame failed for type %d: %v", frameType, err)
		}

		frame, err := session.ReadFrame(buf)
		if err != nil {
			t.Errorf("ReadFrame failed for type %d: %v", frameType, err)
			continue
		}

		if frame.Type != frameType {
			t.Errorf("frame type mismatch: got %d, want %d", frame.Type, frameType)
		}
	}
}

func TestInvalidFrameType(t *testing.T) {
	session, _ := reflex.NewSession(testSessionKey)
	buf := &bytes.Buffer{}

	err := session.WriteFrame(buf, 0xFF, []byte("test"))
	if err == nil {
		t.Fatal("should reject invalid frame type")
	}
}

func TestEmptyFrame(t *testing.T) {
	session, _ := reflex.NewSession(testSessionKey)
	buf := &bytes.Buffer{}

	err := session.WriteFrame(buf, reflex.FrameTypeData, []byte{})
	if err != nil {
		t.Fatalf("WriteFrame with empty data failed: %v", err)
	}

	frame, err := session.ReadFrame(buf)
	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}

	if len(frame.Payload) == 0 {
		t.Error("empty frame should be padded")
	}
}

func TestLargeFrame(t *testing.T) {
	// Use morphing config with larger MaxSize for large frames
	morphingConfig := &reflex.MorphingConfig{
		Enabled:   true,
		MinSize:   64,
		MaxSize:   20000, // Allow larger frames
		Randomize: false, // Disable randomization for predictable test
	}
	session, _ := reflex.NewSessionWithMorphing(testSessionKey, morphingConfig)
	buf := &bytes.Buffer{}

	largeData := make([]byte, 10000)
	rand.Read(largeData)

	err := session.WriteFrame(buf, reflex.FrameTypeData, largeData)
	if err != nil {
		t.Fatalf("WriteFrame with large data failed: %v", err)
	}

	frame, err := session.ReadFrame(buf)
	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}

	if !bytes.HasPrefix(frame.Payload, largeData) {
		t.Error("large frame payload mismatch")
	}
}

func TestFrameDecryptionFailure(t *testing.T) {
	session, _ := reflex.NewSession(testSessionKey)
	buf := &bytes.Buffer{}

	// Write valid frame
	session.WriteFrame(buf, reflex.FrameTypeData, []byte("test"))

	// Corrupt encrypted payload
	data := buf.Bytes()
	data[len(data)-1] ^= 0xFF // Flip last byte

	corruptedBuf := bytes.NewBuffer(data)
	_, err := session.ReadFrame(corruptedBuf)
	if err == nil {
		t.Fatal("should reject corrupted encrypted payload")
	}
}

func TestFrameIncompleteRead(t *testing.T) {
	session, _ := reflex.NewSession(testSessionKey)
	buf := &bytes.Buffer{}

	// Write partial header
	buf.Write([]byte{0x00, 0x10}) // Only 2 bytes of header

	_, err := session.ReadFrame(buf)
	if err == nil {
		t.Fatal("should reject incomplete header")
	}
}

func TestFrameOversizedPayload(t *testing.T) {
	session, _ := reflex.NewSession(testSessionKey)
	buf := &bytes.Buffer{}

	// Create frame with oversized length
	header := []byte{0xFF, 0xFF, reflex.FrameTypeData} // Max size
	buf.Write(header)
	buf.Write(make([]byte, reflex.MaxFrameSize+1)) // Oversized

	_, err := session.ReadFrame(buf)
	if err == nil {
		t.Fatal("should reject oversized frame")
	}
}
