package reflex

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"testing"
)

func makeTestSessionKey() []byte {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	return key
}

func TestNewSession(t *testing.T) {
	key := makeTestSessionKey()
	sess, err := NewSession(key)
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}
	if sess == nil {
		t.Fatal("session is nil")
	}
	if sess.aead == nil {
		t.Fatal("AEAD cipher is nil")
	}
}

func TestNewSessionInvalidKeyLength(t *testing.T) {
	_, err := NewSession([]byte("short"))
	if err == nil {
		t.Fatal("expected error for short key")
	}

	_, err = NewSession(make([]byte, 64))
	if err == nil {
		t.Fatal("expected error for oversized key")
	}

	_, err = NewSession(nil)
	if err == nil {
		t.Fatal("expected error for nil key")
	}
}

func TestWriteReadFrame(t *testing.T) {
	key := makeTestSessionKey()
	writer, _ := NewSession(key)
	reader, _ := NewSession(key)

	original := []byte("hello, reflex protocol!")
	var buf bytes.Buffer

	if err := writer.WriteFrame(&buf, FrameTypeData, original); err != nil {
		t.Fatalf("WriteFrame failed: %v", err)
	}

	frame, err := reader.ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}

	if frame.Type != FrameTypeData {
		t.Fatalf("expected frame type %d, got %d", FrameTypeData, frame.Type)
	}
	if !bytes.Equal(frame.Payload, original) {
		t.Fatalf("payload mismatch: got %q, want %q", frame.Payload, original)
	}
}

func TestMultipleFrameRoundTrip(t *testing.T) {
	key := makeTestSessionKey()
	writer, _ := NewSession(key)
	reader, _ := NewSession(key)

	messages := []string{"first", "second", "third", "fourth", "fifth"}
	var buf bytes.Buffer

	for _, msg := range messages {
		if err := writer.WriteFrame(&buf, FrameTypeData, []byte(msg)); err != nil {
			t.Fatalf("WriteFrame(%q) failed: %v", msg, err)
		}
	}

	for _, msg := range messages {
		frame, err := reader.ReadFrame(&buf)
		if err != nil {
			t.Fatalf("ReadFrame failed for %q: %v", msg, err)
		}
		if string(frame.Payload) != msg {
			t.Fatalf("expected %q, got %q", msg, string(frame.Payload))
		}
	}
}

func TestFrameTypes(t *testing.T) {
	key := makeTestSessionKey()

	types := []uint8{FrameTypeData, FrameTypePadding, FrameTypeTiming, FrameTypeClose}
	for _, ft := range types {
		writer, _ := NewSession(key)
		reader, _ := NewSession(key)
		var buf bytes.Buffer

		if err := writer.WriteFrame(&buf, ft, []byte("test")); err != nil {
			t.Fatalf("WriteFrame type=%d failed: %v", ft, err)
		}

		frame, err := reader.ReadFrame(&buf)
		if err != nil {
			t.Fatalf("ReadFrame type=%d failed: %v", ft, err)
		}
		if frame.Type != ft {
			t.Fatalf("expected type %d, got %d", ft, frame.Type)
		}
	}
}

func TestWriteCloseFrame(t *testing.T) {
	key := makeTestSessionKey()
	writer, _ := NewSession(key)
	reader, _ := NewSession(key)
	var buf bytes.Buffer

	if err := writer.WriteCloseFrame(&buf); err != nil {
		t.Fatalf("WriteCloseFrame failed: %v", err)
	}

	frame, err := reader.ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}
	if frame.Type != FrameTypeClose {
		t.Fatalf("expected CLOSE frame type, got %d", frame.Type)
	}
}

func TestWritePaddingFrame(t *testing.T) {
	key := makeTestSessionKey()
	writer, _ := NewSession(key)
	reader, _ := NewSession(key)
	var buf bytes.Buffer

	padding := make([]byte, 128)
	if _, err := rand.Read(padding); err != nil {
		t.Fatal(err)
	}

	if err := writer.WritePaddingFrame(&buf, padding); err != nil {
		t.Fatalf("WritePaddingFrame failed: %v", err)
	}

	frame, err := reader.ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}
	if frame.Type != FrameTypePadding {
		t.Fatalf("expected PADDING frame type, got %d", frame.Type)
	}
	if !bytes.Equal(frame.Payload, padding) {
		t.Fatal("padding payload mismatch")
	}
}

func TestEncryptionDecryptionIntegrity(t *testing.T) {
	key := makeTestSessionKey()
	writer, _ := NewSession(key)
	reader, _ := NewSession(key)
	var buf bytes.Buffer

	original := make([]byte, 4096)
	if _, err := rand.Read(original); err != nil {
		t.Fatal(err)
	}

	if err := writer.WriteFrame(&buf, FrameTypeData, original); err != nil {
		t.Fatal(err)
	}

	frame, err := reader.ReadFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(frame.Payload, original) {
		t.Fatal("large payload encryption/decryption failed")
	}
}

func TestDecryptionWithWrongKey(t *testing.T) {
	key1 := makeTestSessionKey()
	key2 := makeTestSessionKey()

	writer, _ := NewSession(key1)
	reader, _ := NewSession(key2)
	var buf bytes.Buffer

	if err := writer.WriteFrame(&buf, FrameTypeData, []byte("secret")); err != nil {
		t.Fatalf("WriteFrame failed: %v", err)
	}

	_, err := reader.ReadFrame(&buf)
	if err == nil {
		t.Fatal("decryption with wrong key should fail")
	}
}

func TestEmptyPayloadFrame(t *testing.T) {
	key := makeTestSessionKey()
	writer, _ := NewSession(key)
	reader, _ := NewSession(key)
	var buf bytes.Buffer

	if err := writer.WriteFrame(&buf, FrameTypeData, []byte{}); err != nil {
		t.Fatal(err)
	}

	frame, err := reader.ReadFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(frame.Payload) != 0 {
		t.Fatalf("expected empty payload, got %d bytes", len(frame.Payload))
	}
}

func TestReadFrameIncompleteHeader(t *testing.T) {
	key := makeTestSessionKey()
	reader, _ := NewSession(key)

	// Only provide 2 of the 3 header bytes
	buf := bytes.NewReader([]byte{0x00, 0x05})
	_, err := reader.ReadFrame(buf)
	if err == nil {
		t.Fatal("expected error for incomplete header")
	}
}

func TestNonceTracker(t *testing.T) {
	tracker := NewNonceTracker(100)

	if !tracker.Check(1) {
		t.Fatal("first check of nonce 1 should succeed")
	}
	if !tracker.Check(2) {
		t.Fatal("first check of nonce 2 should succeed")
	}
	if !tracker.Check(3) {
		t.Fatal("first check of nonce 3 should succeed")
	}
}

func TestNonceTrackerReplayDetection(t *testing.T) {
	tracker := NewNonceTracker(100)

	if !tracker.Check(42) {
		t.Fatal("first check should succeed")
	}
	if tracker.Check(42) {
		t.Fatal("replay of nonce 42 should be rejected")
	}
}

func TestNonceTrackerEviction(t *testing.T) {
	tracker := NewNonceTracker(3)

	tracker.Check(1)
	tracker.Check(2)
	tracker.Check(3)

	// 4th nonce triggers eviction of all previous entries
	if !tracker.Check(4) {
		t.Fatal("nonce 4 should succeed after eviction")
	}

	// After eviction, old nonces are no longer tracked (accepted again)
	if !tracker.Check(1) {
		t.Fatal("nonce 1 should be accepted after eviction")
	}
}

func TestNonceTrackerConcurrency(t *testing.T) {
	tracker := NewNonceTracker(10000)
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n uint64) {
			defer wg.Done()
			tracker.Check(n)
		}(uint64(i))
	}
	wg.Wait()
}

func TestConcurrentWriteRead(t *testing.T) {
	key := makeTestSessionKey()
	writerSess, _ := NewSession(key)
	readerSess, _ := NewSession(key)

	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	messages := []string{"alpha", "bravo", "charlie", "delta"}

	go func() {
		for _, msg := range messages {
			_ = writerSess.WriteFrame(clientConn, FrameTypeData, []byte(msg))
		}
	}()

	for _, expected := range messages {
		frame, err := readerSess.ReadFrame(serverConn)
		if err != nil {
			t.Errorf("ReadFrame failed: %v", err)
			return
		}
		if string(frame.Payload) != expected {
			t.Errorf("expected %q, got %q", expected, string(frame.Payload))
		}
	}
}

func TestSendPaddingControl(t *testing.T) {
	key := makeTestSessionKey()
	writer, _ := NewSession(key)
	reader, _ := NewSession(key)
	var buf bytes.Buffer

	if err := writer.SendPaddingControl(&buf, 1024); err != nil {
		t.Fatal(err)
	}

	frame, err := reader.ReadFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if frame.Type != FrameTypePadding {
		t.Fatalf("expected PADDING type, got %d", frame.Type)
	}
}

func TestSendTimingControl(t *testing.T) {
	key := makeTestSessionKey()
	writer, _ := NewSession(key)
	reader, _ := NewSession(key)
	var buf bytes.Buffer

	if err := writer.SendTimingControl(&buf, 50*1e6); err != nil {
		t.Fatal(err)
	}

	frame, err := reader.ReadFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if frame.Type != FrameTypeTiming {
		t.Fatalf("expected TIMING type, got %d", frame.Type)
	}
}

func TestReadFrameOnClosedPipe(t *testing.T) {
	key := makeTestSessionKey()
	reader, _ := NewSession(key)

	r, w := io.Pipe()
	_ = w.Close()

	_, err := reader.ReadFrame(r)
	if err == nil {
		t.Fatal("expected error reading from closed pipe")
	}
}

func BenchmarkEncryption(b *testing.B) {
	key := makeTestSessionKey()
	sess, _ := NewSession(key)
	data := make([]byte, 1024)
	if _, err := rand.Read(data); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		_ = sess.WriteFrame(&buf, FrameTypeData, data)
	}
}

func BenchmarkEncryptionSizes(b *testing.B) {
	sizes := []int{64, 256, 1024, 4096, 16384}
	for _, size := range sizes {
		b.Run(string(rune('0'+size/1000))+"KB", func(b *testing.B) {
			key := makeTestSessionKey()
			sess, _ := NewSession(key)
			data := make([]byte, size)

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				var buf bytes.Buffer
				_ = sess.WriteFrame(&buf, FrameTypeData, data)
			}
		})
	}
}
