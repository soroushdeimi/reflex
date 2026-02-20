package reflex

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

func createTestKeys() *SessionKeys {
	return &SessionKeys{
		ClientToServer: make([]byte, 32),
		ServerToClient: make([]byte, 32),
	}
}

func TestSessionReadWrite(t *testing.T) {
	keys := createTestKeys()
	serverSess, _ := NewServerSession(keys)
	clientSess, _ := NewClientSession(keys)

	buf := new(bytes.Buffer)
	payload := []byte("test-data-payload")

	// 1. Client Write -> Server Read
	err := clientSess.WriteFrame(buf, FrameTypeData, payload, false)
	if err != nil {
		t.Fatal("client write failed:", err)
	}

	frame, err := serverSess.ReadFrame(buf, true)
	if err != nil {
		t.Fatal("server read failed:", err)
	}

	if !bytes.Equal(frame.Payload, payload) {
		t.Error("payload data mismatch")
	}

	// 2. Server Write -> Client Read
	buf.Reset()
	err = serverSess.WriteFrame(buf, FrameTypeData, payload, true)
	if err != nil {
		t.Fatal("server write failed:", err)
	}

	frame, err = clientSess.ReadFrame(buf, false)
	if err != nil {
		t.Fatal("client read failed:", err)
	}

	if !bytes.Equal(frame.Payload, payload) {
		t.Error("payload data mismatch")
	}
}

func TestSessionMorphing(t *testing.T) {
	keys := createTestKeys()
	profile := YouTubeProfile
	sess, _ := NewServerSessionWithMorphing(keys, profile)

	if !sess.IsMorphingEnabled() {
		t.Error("morphing should be enabled")
	}

	buf := new(bytes.Buffer)
	data := make([]byte, 100) // Small data to be padded

	// Test morphing write
	err := sess.WriteFrameWithMorphing(buf, FrameTypeData, data, true)
	if err != nil {
		t.Fatal("morphed write failed:", err)
	}

	// Buffer should contain at least one morphed packet (Header 3 + Encrypted Payload)
	if buf.Len() <= 100 {
		t.Error("buffer size suggests no padding was added")
	}
}

func TestControlFrames(t *testing.T) {
	keys := createTestKeys()
	sess, _ := NewServerSessionWithMorphing(keys, YouTubeProfile)

	// 1. Test Padding Control
	targetSize := uint16(2000)
	payload := make([]byte, 2)
	binary.BigEndian.PutUint16(payload, targetSize)

	f := &Frame{Type: FrameTypePadding, Payload: payload}
	sess.HandleControlFrame(f)

	if sess.morphingProfile.nextSize != int(targetSize) {
		t.Error("failed to handle padding control frame")
	}

	// 2. Test Timing Control
	delay := uint64(500)
	payload = make([]byte, 8)
	binary.BigEndian.PutUint64(payload, delay)

	f = &Frame{Type: FrameTypeTiming, Payload: payload}
	sess.HandleControlFrame(f)

	if sess.morphingProfile.nextDelay != 500*time.Millisecond {
		t.Error("failed to handle timing control frame")
	}
}

func TestReplayProtection(t *testing.T) {
	keys := createTestKeys()
	serverSess, _ := NewServerSession(keys)
	clientSess, _ := NewClientSession(keys)

	buf := new(bytes.Buffer)
	clientSess.WriteFrame(buf, FrameTypeData, []byte("data"), false)

	// First read success
	raw := buf.Bytes()
	_, err := serverSess.ReadFrame(bytes.NewReader(raw), true)
	if err != nil {
		t.Fatal("first read should succeed")
	}

	// Replay same data should fail
	_, err = serverSess.ReadFrame(bytes.NewReader(raw), true)
	if err == nil {
		t.Error("expected error for replayed packet")
	}
}

func TestNonceCounters(t *testing.T) {
	keys := createTestKeys()
	sess, _ := NewServerSession(keys)

	if sess.GetWriteNonce() != 0 {
		t.Error("initial nonce should be 0")
	}

	sess.WriteFrame(new(bytes.Buffer), FrameTypeData, []byte("d"), true)
	if sess.GetWriteNonce() != 1 {
		t.Error("write nonce should increment")
	}

	sess.ResetNonces()
	if sess.GetWriteNonce() != 0 {
		t.Error("reset nonces failed")
	}
}
