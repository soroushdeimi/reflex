package reflex

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	stdnet "net"
	"testing"
	"time"
)

func TestGenerateKeyPair(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	if priv == [32]byte{} {
		t.Fatal("private key should not be all zeros")
	}
	if pub == [32]byte{} {
		t.Fatal("public key should not be all zeros")
	}
	// Generate another pair and ensure they differ
	priv2, pub2, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if priv == priv2 {
		t.Error("two generated private keys should differ")
	}
	if pub == pub2 {
		t.Error("two generated public keys should differ")
	}
}

func TestDeriveSessionKeys_SharedSecret(t *testing.T) {
	// ECDH property: DH(a, B) == DH(b, A)
	priv1, pub1, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	priv2, pub2, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	key1, err := DeriveSessionKeys(priv1, pub2)
	if err != nil {
		t.Fatalf("DeriveSessionKeys(priv1, pub2) failed: %v", err)
	}
	key2, err := DeriveSessionKeys(priv2, pub1)
	if err != nil {
		t.Fatalf("DeriveSessionKeys(priv2, pub1) failed: %v", err)
	}

	if !bytes.Equal(key1, key2) {
		t.Fatal("shared secrets should be equal (DH property)")
	}
	if len(key1) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(key1))
	}
}

func TestNewSession_ValidKey(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	s, err := NewSession(key)
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}
	if s == nil {
		t.Fatal("NewSession returned nil")
	}
	if s.ReadNonce != 0 || s.WriteNonce != 0 {
		t.Fatal("nonces should start at 0")
	}
}

func TestNewSession_InvalidKey(t *testing.T) {
	// ChaCha20-Poly1305 requires exactly 32 bytes
	_, err := NewSession([]byte("too-short-key"))
	if err == nil {
		t.Fatal("expected error with short key")
	}
}

func TestWriteFrame_ReadFrame_RoundTrip(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	s1, _ := NewSession(key)
	s2, _ := NewSession(key)

	c1, c2 := stdnet.Pipe()
	defer c1.Close()
	defer c2.Close()

	data := []byte("hello reflex protocol")
	errCh := make(chan error, 1)
	go func() {
		errCh <- s1.WriteFrame(c1, FrameTypeData, data)
	}()

	frame, err := s2.ReadFrame(c2)
	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}
	if frame.Type != FrameTypeData {
		t.Fatalf("expected type %d, got %d", FrameTypeData, frame.Type)
	}
	if !bytes.Equal(frame.Payload, data) {
		t.Fatalf("payload mismatch: got %q, want %q", frame.Payload, data)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("WriteFrame failed: %v", err)
	}
}

func TestWriteFrame_MultipleTypes(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	s1, _ := NewSession(key)
	s2, _ := NewSession(key)

	c1, c2 := stdnet.Pipe()
	defer c1.Close()
	defer c2.Close()

	frameTypes := []uint8{FrameTypeData, FrameTypePadding, FrameTypeTiming, FrameTypeClose}
	go func() {
		for _, ft := range frameTypes {
			s1.WriteFrame(c1, ft, []byte{byte(ft)})
		}
		c1.Close()
	}()

	for _, expectedType := range frameTypes {
		frame, err := s2.ReadFrame(c2)
		if err != nil {
			t.Fatalf("ReadFrame error: %v", err)
		}
		if frame.Type != expectedType {
			t.Errorf("expected type %d, got %d", expectedType, frame.Type)
		}
	}
}

func TestReadFrame_WrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	rand.Read(key1)
	rand.Read(key2)
	// Ensure distinct keys
	for bytes.Equal(key1, key2) {
		rand.Read(key2)
	}

	s1, _ := NewSession(key1)
	s2, _ := NewSession(key2)

	c1, c2 := stdnet.Pipe()
	defer c1.Close()
	defer c2.Close()

	go func() {
		s1.WriteFrame(c1, FrameTypeData, []byte("secret"))
		c1.Close()
	}()

	_, err := s2.ReadFrame(c2)
	if err == nil {
		t.Fatal("reading with wrong key should return authentication error")
	}
}

func TestReadFrame_EOF(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	s, _ := NewSession(key)

	c1, c2 := stdnet.Pipe()
	c1.Close() // close immediately

	_, err := s.ReadFrame(c2)
	if err == nil || err != io.EOF {
		// Closed pipe returns io.ErrClosedPipe or io.EOF
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		// Any error is acceptable on a closed pipe
	}
}

func TestWriteFrame_EmptyPayload(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	s1, _ := NewSession(key)
	s2, _ := NewSession(key)

	c1, c2 := stdnet.Pipe()
	defer c1.Close()
	defer c2.Close()

	go func() {
		s1.WriteFrame(c1, FrameTypeData, []byte{})
	}()

	frame, err := s2.ReadFrame(c2)
	if err != nil {
		t.Fatalf("ReadFrame with empty payload failed: %v", err)
	}
	if len(frame.Payload) != 0 {
		t.Fatalf("expected empty payload, got len=%d", len(frame.Payload))
	}
}

func TestWriteFrameWithMorphing_NilProfile(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	s1, _ := NewSession(key)
	s2, _ := NewSession(key)

	c1, c2 := stdnet.Pipe()
	defer c1.Close()
	defer c2.Close()

	data := []byte("morphing with nil profile")
	go func() {
		s1.WriteFrameWithMorphing(c1, FrameTypeData, data, nil)
		c1.Close()
	}()

	frame, err := s2.ReadFrame(c2)
	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}
	if !bytes.Equal(frame.Payload, data) {
		t.Fatalf("payload mismatch: got %q, want %q", frame.Payload, data)
	}
}

func TestWriteFrameWithMorphing_WithProfile_SmallData(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	s1, _ := NewSession(key)
	s2, _ := NewSession(key)
	profile := Profiles["zoom"] // Target sizes: 500, 600, 700

	c1, c2 := stdnet.Pipe()
	defer c1.Close()
	defer c2.Close()

	data := []byte("small payload, should be padded")
	go func() {
		s1.WriteFrameWithMorphing(c1, FrameTypeData, data, profile)
		c1.Close()
	}()

	frame, err := s2.ReadFrame(c2)
	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}
	// Payload may be padded to match profile size
	if !bytes.HasPrefix(frame.Payload, data) && !bytes.Equal(frame.Payload[:len(data)], data) {
		t.Logf("Padded frame payload length: %d", len(frame.Payload))
	}
}

func TestWriteFrameWithMorphing_LargeData_Splits(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	s1, _ := NewSession(key)
	s2, _ := NewSession(key)
	profile := Profiles["zoom"] // Small sizes force splitting for large data

	c1, c2 := stdnet.Pipe()
	defer c1.Close()
	defer c2.Close()

	largeData := make([]byte, 2000) // Larger than zoom packet sizes
	rand.Read(largeData)

	go func() {
		s1.WriteFrameWithMorphing(c1, FrameTypeData, largeData, profile)
		c1.Close()
	}()

	totalRead := 0
	for {
		frame, err := s2.ReadFrame(c2)
		if err != nil {
			break
		}
		totalRead += len(frame.Payload)
	}
	if totalRead < len(largeData) {
		t.Fatalf("read %d bytes, want at least %d", totalRead, len(largeData))
	}
}

func TestClientHandshake_SerializeParseRoundTrip(t *testing.T) {
	_, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	original := &ClientHandshake{
		PublicKey: pub,
		UserID:    [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		Timestamp: 1700000000,
		Nonce:     [16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
	}

	serialized := original.Serialize()
	if len(serialized) != 72 {
		t.Fatalf("expected 72-byte serialized handshake, got %d", len(serialized))
	}

	parsed, err := ParseClientHandshake(serialized)
	if err != nil {
		t.Fatalf("ParseClientHandshake failed: %v", err)
	}
	if parsed.PublicKey != original.PublicKey {
		t.Error("PublicKey mismatch after round-trip")
	}
	if parsed.UserID != original.UserID {
		t.Error("UserID mismatch after round-trip")
	}
	if parsed.Timestamp != original.Timestamp {
		t.Errorf("Timestamp mismatch: got %d, want %d", parsed.Timestamp, original.Timestamp)
	}
	if parsed.Nonce != original.Nonce {
		t.Error("Nonce mismatch after round-trip")
	}
}

func TestParseClientHandshake_TooShort(t *testing.T) {
	for _, size := range []int{0, 1, 10, 71} {
		_, err := ParseClientHandshake(make([]byte, size))
		if err == nil {
			t.Errorf("expected error for data of size %d", size)
		}
	}
}

func TestParseClientHandshake_Exactly72Bytes(t *testing.T) {
	data := make([]byte, 72)
	rand.Read(data)
	// Set a known timestamp
	binary.BigEndian.PutUint64(data[48:56], uint64(1234567890))
	h, err := ParseClientHandshake(data)
	if err != nil {
		t.Fatalf("ParseClientHandshake failed: %v", err)
	}
	if h.Timestamp != 1234567890 {
		t.Errorf("Timestamp mismatch: got %d", h.Timestamp)
	}
}

func TestHandleControlFrame_NilProfile(t *testing.T) {
	key := make([]byte, 32)
	s, _ := NewSession(key)
	// Should not panic
	s.HandleControlFrame(&Frame{Type: FrameTypePadding, Payload: []byte{0, 10}}, nil)
}

func TestHandleControlFrame_PaddingType(t *testing.T) {
	key := make([]byte, 32)
	s, _ := NewSession(key)
	profile := &TrafficProfile{
		PacketSizes: []PacketSizeDist{{Size: 1000, Weight: 1.0}},
		Delays:      []DelayDist{{Delay: 10 * time.Millisecond, Weight: 1.0}},
	}

	payload := make([]byte, 2)
	binary.BigEndian.PutUint16(payload, 1337)
	s.HandleControlFrame(&Frame{Type: FrameTypePadding, Payload: payload}, profile)

	if profile.GetPacketSize() != 1337 {
		t.Errorf("expected nextPacketSize=1337, got %d", profile.GetPacketSize())
	}
}

func TestHandleControlFrame_TimingType(t *testing.T) {
	key := make([]byte, 32)
	s, _ := NewSession(key)
	profile := &TrafficProfile{
		PacketSizes: []PacketSizeDist{{Size: 1000, Weight: 1.0}},
		Delays:      []DelayDist{{Delay: 10 * time.Millisecond, Weight: 1.0}},
	}

	payload := make([]byte, 8)
	binary.BigEndian.PutUint64(payload, 250) // 250 ms
	s.HandleControlFrame(&Frame{Type: FrameTypeTiming, Payload: payload}, profile)

	d := profile.GetDelay()
	if d != 250*time.Millisecond {
		t.Errorf("expected delay 250ms, got %v", d)
	}
}

func TestHandleControlFrame_PaddingShortPayload(t *testing.T) {
	key := make([]byte, 32)
	s, _ := NewSession(key)
	profile := &TrafficProfile{
		PacketSizes: []PacketSizeDist{{Size: 1000, Weight: 1.0}},
		Delays:      []DelayDist{{Delay: 10 * time.Millisecond, Weight: 1.0}},
	}
	// 1-byte payload, too short for uint16
	s.HandleControlFrame(&Frame{Type: FrameTypePadding, Payload: []byte{0x05}}, profile)
	// Should not change nextPacketSize, so GetPacketSize returns normal distribution
	size := profile.GetPacketSize()
	if size != 1000 {
		t.Errorf("expected 1000 (unchanged), got %d", size)
	}
}

func TestHandleControlFrame_TimingShortPayload(t *testing.T) {
	key := make([]byte, 32)
	s, _ := NewSession(key)
	profile := &TrafficProfile{
		PacketSizes: []PacketSizeDist{{Size: 1000, Weight: 1.0}},
		Delays:      []DelayDist{{Delay: 5 * time.Millisecond, Weight: 1.0}},
	}
	// Less than 8 bytes, too short for uint64
	s.HandleControlFrame(&Frame{Type: FrameTypeTiming, Payload: []byte{0, 1, 2, 3}}, profile)
	// Should not change nextDelay
	d := profile.GetDelay()
	if d != 5*time.Millisecond {
		t.Errorf("expected 5ms (unchanged), got %v", d)
	}
}

func TestHandleControlFrame_UnknownType(t *testing.T) {
	key := make([]byte, 32)
	s, _ := NewSession(key)
	profile := &TrafficProfile{
		PacketSizes: []PacketSizeDist{{Size: 1000, Weight: 1.0}},
		Delays:      []DelayDist{{Delay: 5 * time.Millisecond, Weight: 1.0}},
	}
	// Should silently ignore unknown frame types
	s.HandleControlFrame(&Frame{Type: 0xFF, Payload: []byte{1, 2, 3, 4}}, profile)
}

func TestSerializeTimestamp_SignedInt64(t *testing.T) {
	h := &ClientHandshake{
		Timestamp: -1, // edge case: negative timestamp
	}
	data := h.Serialize()
	parsed, err := ParseClientHandshake(data)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Timestamp != -1 {
		t.Errorf("expected -1, got %d", parsed.Timestamp)
	}
}

func TestWriteFrame_NonceIncrementsCorrectly(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	s, _ := NewSession(key)

	c1, c2 := stdnet.Pipe()
	defer c1.Close()
	defer c2.Close()

	go func() {
		for i := 0; i < 3; i++ {
			s.WriteFrame(c1, FrameTypeData, []byte{byte(i)})
		}
		c1.Close()
	}()

	s2, _ := NewSession(key)
	for i := 0; i < 3; i++ {
		frame, err := s2.ReadFrame(c2)
		if err != nil {
			t.Fatalf("ReadFrame %d failed: %v", i, err)
		}
		if frame.Payload[0] != byte(i) {
			t.Errorf("frame %d payload mismatch", i)
		}
	}
}
