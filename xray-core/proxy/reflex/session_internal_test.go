package reflex

import (
	"bytes"
	"testing"
)

func TestSessionDataIntegrityWithPadding(t *testing.T) {
	key := make([]byte, 32)
	sess, _ := NewSession(key)
	
	originalData := []byte("secret payload")
	buffer := new(bytes.Buffer)

	profile := &YouTubeProfile
	err := sess.WriteFrameWithMorphing(buffer, FrameTypeData, originalData, profile)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	frame, err := sess.ReadFrame(buffer)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if !bytes.Equal(frame.Payload, originalData) {
		t.Errorf("Data corruption! Expected %s, got %s", originalData, frame.Payload)
	}
}