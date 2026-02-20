package inbound

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

func generateTestKey() []byte {
	k := make([]byte, 32)
	rand.Read(k)
	return k
}

func TestEndToEndSession(t *testing.T) {
	sess, err := NewSession(generateTestKey())
	if err != nil {
		t.Fatal(err)
	}

	var stream bytes.Buffer
	srcData := []byte("secret_payload")

	if err := sess.WriteFrame(&stream, FrameTypeData, srcData); err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	res, err := sess.ReadFrame(&stream)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	if res.Type != FrameTypeData {
		t.Error("Frame type mismatch after decryption")
	}
	if !bytes.Equal(res.Payload, srcData) {
		t.Error("Decrypted data does not match original")
	}
}

func TestAntiReplayMechanism(t *testing.T) {
	sess, _ := NewSession(generateTestKey())
	var stream bytes.Buffer

	sess.WriteFrame(&stream, FrameTypeData, []byte("uniq_data"))
	capturedBytes := stream.Bytes()

	playback := bytes.NewReader(capturedBytes)

	if _, err := sess.ReadFrame(playback); err != nil {
		t.Fatalf("First read should succeed, got: %v", err)
	}

	if _, err := sess.ReadFrame(playback); err == nil {
		t.Fatal("Replay attack was not blocked by AEAD")
	}
}

func TestMultiFrameSequence(t *testing.T) {
	sess, _ := NewSession(generateTestKey())
	var pipe bytes.Buffer

	chunks := [][]byte{
		[]byte("first_chunk"),
		[]byte("second_chunk"),
		[]byte(""),
	}

	for idx, chunk := range chunks {
		if err := sess.WriteFrame(&pipe, FrameTypeData, chunk); err != nil {
			t.Fatalf("Failed writing frame %d: %v", idx, err)
		}
	}

	consumer := bytes.NewReader(pipe.Bytes())

	for idx, expected := range chunks {
		frm, err := sess.ReadFrame(consumer)
		if err != nil {
			t.Fatalf("Failed reading frame %d: %v", idx, err)
		}
		if !bytes.Equal(frm.Payload, expected) {
			t.Errorf("Mismatch at frame %d", idx)
		}
	}

	if _, err := sess.ReadFrame(consumer); err != io.EOF && err != nil {
		t.Errorf("Expected clear EOF, got %v", err)
	}
}