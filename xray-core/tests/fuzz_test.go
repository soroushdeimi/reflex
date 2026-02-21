package reflex_test

import (
	"bytes"
	"testing"
	"github.com/xtls/xray-core/proxy/reflex"
)

// FuzzReadFrame tests the resilience of frame parsing against malformed input.
func FuzzReadFrame(f *testing.F) {
	key := make([]byte, 32)
	session, _ := reflex.NewSession(key, key)

	// Add some seed corpus
	f.Add([]byte{0, 0, 1})                   // Short header
	f.Add([]byte{0, 5, 1, 1, 2, 3, 4, 5})    // Incomplete payload
	f.Add(make([]byte, 100))                 // All zeros

	f.Fuzz(func(t *testing.T, data []byte) {
		reader := bytes.NewReader(data)
		_, _ = session.ReadFrame(reader)
	})
}
