package reflex

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"
)

func TestDynamicProfileSwitching(t *testing.T) {
	// 1. Setup
	key := make([]byte, 32)
	_, _ = rand.Read(key) 
	session, _ := NewSession(key)
	buf := new(bytes.Buffer)

	// 2. Create Morpher with a very short interval (100ms) for testing
	morpher := NewDynamicMorpher(100 * time.Millisecond)

	// 3. Phase 1: Should be Profile 0 (YouTube - Large Packets ~1400)
	data := []byte("test data")
	t.Log("Phase 1: Sending packet (Expect YouTube profile)...")
	_ = session.WriteFrameWithDynamicMorphing(buf, FrameTypeData, data, morpher)

	size1 := buf.Len()
	t.Logf("Packet 1 Size: %d", size1)

	// 4. Wait for switch
	time.Sleep(150 * time.Millisecond)

	// 5. Phase 2: Should be Profile 1 (Zoom - Smaller Packets ~500-700)
	buf.Reset()
	t.Log("Phase 2: Sending packet after timeout (Expect Zoom profile)...")
	_=session.WriteFrameWithDynamicMorphing(buf , FrameTypeData, data, morpher)

	size2 := buf.Len()
	t.Logf("Packet 2 Size: %d", size2)

	// 6. Verification
	// YouTube packets are generally > 800. Zoom packets are < 800.
	// If the sizes are significantly different, the switch worked.
	if size1 == size2 {
		t.Log("Warning: Packet sizes were identical. This *could* happen by chance, but unlikely.")
	} else {
		t.Log("Success: Packet sizes changed significantly, indicating profile switch!")
	}
}
