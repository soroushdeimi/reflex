package inbound

import (
	"bufio"
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestReplayProtectionRejectsReplayedFrame(t *testing.T) {
	key := bytes.Repeat([]byte{0xAB}, 32)
	writerSession, err := NewSession(key)
	if err != nil {
		t.Fatalf("failed to create writer session: %v", err)
	}
	readerSession, err := NewSession(key)
	if err != nil {
		t.Fatalf("failed to create reader session: %v", err)
	}

	testData := []byte("test data")
	var wire bytes.Buffer
	if err := writerSession.WriteFrame(&wire, FrameTypeData, testData); err != nil {
		t.Fatalf("failed to write frame: %v", err)
	}
	raw := wire.Bytes()

	// First read with nonce=0 should succeed.
	frame1, err := readerSession.ReadFrame(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("first read should succeed: %v", err)
	}
	if !bytes.Equal(frame1.Payload, testData) {
		t.Fatal("payload mismatch on first read")
	}

	// Replaying the exact same ciphertext should fail because reader nonce advanced to 1.
	if _, err := readerSession.ReadFrame(bytes.NewReader(raw)); err == nil {
		t.Fatal("expected replayed frame decryption to fail")
	}
}

func TestNonceUniquenessMonotonicCounters(t *testing.T) {
	key := bytes.Repeat([]byte{0xCD}, 32)
	writerSession, err := NewSession(key)
	if err != nil {
		t.Fatalf("failed to create writer session: %v", err)
	}
	readerSession, err := NewSession(key)
	if err != nil {
		t.Fatalf("failed to create reader session: %v", err)
	}

	numFrames := 8
	var wire bytes.Buffer
	for i := 0; i < numFrames; i++ {
		payload := []byte{byte(i)}
		if err := writerSession.WriteFrame(&wire, FrameTypeData, payload); err != nil {
			t.Fatalf("failed to write frame %d: %v", i, err)
		}
	}

	reader := bytes.NewReader(wire.Bytes())
	for i := 0; i < numFrames; i++ {
		frame, err := readerSession.ReadFrame(reader)
		if err != nil {
			t.Fatalf("failed to read frame %d: %v", i, err)
		}
		if len(frame.Payload) != 1 || frame.Payload[0] != byte(i) {
			t.Fatalf("payload mismatch for frame %d", i)
		}
	}

	if writerSession.writeNonce != uint64(numFrames) {
		t.Fatalf("unexpected writer nonce: got %d want %d", writerSession.writeNonce, numFrames)
	}
	if readerSession.readNonce != uint64(numFrames) {
		t.Fatalf("unexpected reader nonce: got %d want %d", readerSession.readNonce, numFrames)
	}
}

func TestTimestampValidationInProcessHandshake(t *testing.T) {
	h := createTestHandler()
	validUser := uuid.MustParse(h.clients[0].Account.(*MemoryAccount).Id)
	conn := &bufferConn{}
	hs := &ClientHandshake{
		UserID:    [16]byte(validUser),
		Timestamp: time.Now().Unix() - 601,
	}

	err := h.processHandshake(
		bufio.NewReader(bytes.NewReader(nil)),
		conn,
		&testDispatcher{},
		context.Background(),
		hs,
	)
	if err == nil {
		t.Fatal("expected timestamp validation error")
	}
	if !strings.Contains(err.Error(), "timestamp out of range") {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Contains(conn.Bytes(), []byte("403 Forbidden")) ||
		!bytes.Contains(conn.Bytes(), []byte("invalid timestamp")) {
		t.Fatal("expected 403 response with invalid timestamp message")
	}
}
