package reflex_test

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/proxy/reflex"
)

// Tests in this file mirror tests/reflex_test.go so that coverage is attributed to the reflex package.

func TestReplayProtection(t *testing.T) {
	key := make([]byte, 32)
	sess, err := reflex.NewSession(key)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := sess.WriteFrame(&buf, reflex.FrameTypeData, []byte("once")); err != nil {
		t.Fatal(err)
	}
	frameBytes := buf.Bytes()

	readSess, _ := reflex.NewSession(key)
	_, err = readSess.ReadFrame(bytes.NewReader(frameBytes))
	if err != nil {
		t.Fatalf("first read failed: %v", err)
	}
	_, err = readSess.ReadFrame(bytes.NewReader(frameBytes))
	if err == nil {
		t.Fatal("replay should have failed (decrypt with wrong nonce)")
	}
}

func TestSessionEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	sess, err := reflex.NewSession(key)
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}

	payload := []byte("hello reflex")
	var buf bytes.Buffer

	if err := sess.WriteFrame(&buf, reflex.FrameTypeData, payload); err != nil {
		t.Fatalf("WriteFrame failed: %v", err)
	}

	readSess, err := reflex.NewSession(key)
	if err != nil {
		t.Fatalf("NewSession (read) failed: %v", err)
	}

	frame, err := readSess.ReadFrame(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}

	if frame.Type != reflex.FrameTypeData {
		t.Fatalf("unexpected frame type: got %d, want %d", frame.Type, reflex.FrameTypeData)
	}
	if !bytes.Equal(frame.Payload, payload) {
		t.Fatalf("payload mismatch: got %q, want %q", frame.Payload, payload)
	}
}

func TestTrafficProfileBasic(t *testing.T) {
	key := make([]byte, 32)
	sess, err := reflex.NewSession(key)
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}

	profile := &reflex.TrafficProfile{
		PacketSizes: []reflex.PacketSizeDist{{Size: 600, Weight: 1}},
		Delays:      []reflex.DelayDist{{Delay: 5 * time.Millisecond, Weight: 1}},
	}

	size := profile.GetPacketSize()
	if size != 600 {
		t.Fatalf("GetPacketSize returned %d, want 600", size)
	}

	var buf bytes.Buffer
	data := []byte("morph-test")
	if err := sess.WriteFrameWithMorphing(&buf, reflex.FrameTypeData, data, profile); err != nil {
		t.Fatalf("WriteFrameWithMorphing failed: %v", err)
	}

	readSess, err := reflex.NewSession(key)
	if err != nil {
		t.Fatalf("NewSession (read) failed: %v", err)
	}

	frame, err := readSess.ReadFrame(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}
	if frame.Type != reflex.FrameTypeData {
		t.Fatalf("unexpected frame type: got %d, want %d", frame.Type, reflex.FrameTypeData)
	}
	if len(frame.Payload) != 602 {
		t.Fatalf("expected morphed payload size 602 (2+600), got %d", len(frame.Payload))
	}
	stripped, ok := reflex.StripMorphingPrefix(frame.Payload)
	if !ok {
		t.Fatalf("StripMorphingPrefix failed")
	}
	if !bytes.Equal(stripped, data) {
		t.Fatalf("stripped payload should equal original data %q, got %q", data, stripped)
	}
}

func TestDecodeClientHandshakePacket(t *testing.T) {
	var hs reflex.ClientHandshake
	copy(hs.PublicKey[:], bytes.Repeat([]byte{0x11}, 32))
	copy(hs.UserID[:], bytes.Repeat([]byte{0x22}, 16))
	hs.PolicyReq = []byte{0x33, 0x44}
	hs.Timestamp = 123456789

	packet := &reflex.ClientHandshakePacket{
		Magic:     reflex.ReflexMagic,
		Handshake: hs,
	}

	data := reflex.EncodeClientHandshakePacket(packet)
	decoded, err := reflex.DecodeClientHandshakePacket(data)
	if err != nil {
		t.Fatalf("DecodeClientHandshakePacket failed: %v", err)
	}

	if decoded.Magic != reflex.ReflexMagic {
		t.Fatalf("magic mismatch: got %x, want %x", decoded.Magic, reflex.ReflexMagic)
	}
	if decoded.Handshake.Timestamp != hs.Timestamp {
		t.Fatalf("timestamp mismatch: got %d, want %d", decoded.Handshake.Timestamp, hs.Timestamp)
	}
	if !bytes.Equal(decoded.Handshake.PolicyReq, hs.PolicyReq) {
		t.Fatalf("policyReq mismatch: got %v, want %v", decoded.Handshake.PolicyReq, hs.PolicyReq)
	}
}

func TestSessionControlFrames(t *testing.T) {
	profile := &reflex.TrafficProfile{
		PacketSizes: []reflex.PacketSizeDist{{Size: 1000, Weight: 1}},
		Delays:      []reflex.DelayDist{{Delay: 10 * time.Millisecond, Weight: 1}},
	}

	key := make([]byte, 32)
	sess, err := reflex.NewSession(key)
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}

	paddingPayload := make([]byte, 2)
	binary.BigEndian.PutUint16(paddingPayload, 512)
	paddingFrame := &reflex.Frame{Type: reflex.FrameTypePadding, Payload: paddingPayload}
	sess.HandleControlFrame(paddingFrame, profile)

	if got := profile.GetPacketSize(); got != 512 {
		t.Fatalf("expected next packet size override 512, got %d", got)
	}
}

func TestEmptyData(t *testing.T) {
	key := make([]byte, 32)
	sess, err := reflex.NewSession(key)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := sess.WriteFrame(&buf, reflex.FrameTypeData, []byte{}); err != nil {
		t.Fatalf("WriteFrame empty: %v", err)
	}
	readSess, _ := reflex.NewSession(key)
	frame, err := readSess.ReadFrame(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if len(frame.Payload) != 0 {
		t.Fatalf("expected empty payload, got len %d", len(frame.Payload))
	}
}

func TestLargeData(t *testing.T) {
	key := make([]byte, 32)
	sess, err := reflex.NewSession(key)
	if err != nil {
		t.Fatal(err)
	}
	const maxPayload = 65519
	largeData := make([]byte, maxPayload)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}
	var buf bytes.Buffer
	if err := sess.WriteFrame(&buf, reflex.FrameTypeData, largeData); err != nil {
		t.Fatalf("WriteFrame large: %v", err)
	}
	readSess, _ := reflex.NewSession(key)
	frame, err := readSess.ReadFrame(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if !bytes.Equal(frame.Payload, largeData) {
		t.Fatal("large payload mismatch")
	}
}

func TestClosedConnection(t *testing.T) {
	key := make([]byte, 32)
	sess, err := reflex.NewSession(key)
	if err != nil {
		t.Fatal(err)
	}
	clientConn, serverConn := net.Pipe()
	serverConn.Close()
	_, _ = clientConn.Write(nil)
	clientConn.Close()
	closedConn, _ := net.Pipe()
	closedConn.Close()
	err = sess.WriteFrame(closedConn, reflex.FrameTypeData, []byte("test"))
	if err == nil {
		t.Fatal("expected error when writing to closed connection")
	}
}

func TestConnectionReset(t *testing.T) {
	key := make([]byte, 32)
	sess, err := reflex.NewSession(key)
	if err != nil {
		t.Fatal(err)
	}
	clientConn, serverConn := net.Pipe()
	go func() {
		_ = sess.WriteFrame(clientConn, reflex.FrameTypeData, []byte("test"))
	}()
	time.Sleep(10 * time.Millisecond)
	serverConn.Close()
	clientConn.Close()
}

func TestOversizedPayload(t *testing.T) {
	key := make([]byte, 32)
	sess, err := reflex.NewSession(key)
	if err != nil {
		t.Fatal(err)
	}
	const maxPayload = 65519
	hugeData := make([]byte, maxPayload)
	for i := range hugeData {
		hugeData[i] = byte(i & 0xff)
	}
	var buf bytes.Buffer
	err = sess.WriteFrame(&buf, reflex.FrameTypeData, hugeData)
	if err != nil {
		t.Fatalf("WriteFrame max payload: %v", err)
	}
	readSess, _ := reflex.NewSession(key)
	frame, err := readSess.ReadFrame(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if len(frame.Payload) != len(hugeData) {
		t.Fatalf("payload len %d, want %d", len(frame.Payload), len(hugeData))
	}
	if !bytes.Equal(frame.Payload, hugeData) {
		t.Fatal("payload content mismatch")
	}
}

func TestStripMorphingPrefix_NoPadding(t *testing.T) {
	// Payload with no padding (length prefix + exactly that many bytes, no extra) should not be stripped.
	payload := []byte{0x00, 0x05, 'h', 'e', 'l', 'l', 'o'} // length=5, exactly 5 bytes data, no padding
	data, ok := reflex.StripMorphingPrefix(payload)
	if ok {
		t.Fatal("StripMorphingPrefix should return false when paddingLen is 0")
	}
	if !bytes.Equal(data, payload) {
		t.Fatal("when not stripped should return original payload unchanged")
	}
}

func TestWriteFrameWithMorphing_NonDataFrame(t *testing.T) {
	key := make([]byte, 32)
	sess, err := reflex.NewSession(key)
	if err != nil {
		t.Fatal(err)
	}
	profile := &reflex.TrafficProfile{
		PacketSizes: []reflex.PacketSizeDist{{Size: 600, Weight: 1}},
		Delays:      []reflex.DelayDist{{Delay: 0, Weight: 1}},
	}
	var buf bytes.Buffer
	// WriteFrameWithMorphing with FrameTypeClose should use regular WriteFrame (no morphing).
	err = sess.WriteFrameWithMorphing(&buf, reflex.FrameTypeClose, nil, profile)
	if err != nil {
		t.Fatalf("WriteFrameWithMorphing close: %v", err)
	}
	readSess, _ := reflex.NewSession(key)
	frame, err := readSess.ReadFrame(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if frame.Type != reflex.FrameTypeClose {
		t.Fatalf("expected FrameTypeClose, got %d", frame.Type)
	}
}
