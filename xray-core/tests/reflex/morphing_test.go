package reflex_test

import (
	"bytes"
	"testing"

	"github.com/xtls/xray-core/proxy/reflex"
)

func TestDefaultMorphingConfig(t *testing.T) {
	config := reflex.DefaultMorphingConfig()

	if !config.Enabled {
		t.Error("morphing should be enabled by default")
	}
	if config.MinSize != 64 {
		t.Errorf("min size mismatch: got %d, want 64", config.MinSize)
	}
	if config.MaxSize != 1500 {
		t.Errorf("max size mismatch: got %d, want 1500", config.MaxSize)
	}
	if !config.Randomize {
		t.Error("randomize should be enabled by default")
	}
}

func TestApplyMorphingDisabled(t *testing.T) {
	config := &reflex.MorphingConfig{Enabled: false}
	data := []byte("test")

	result := reflex.ApplyMorphing(data, config)
	if !bytes.Equal(result, data) {
		t.Error("morphing should not modify data when disabled")
	}
}

func TestApplyMorphingSmallPacket(t *testing.T) {
	config := reflex.DefaultMorphingConfig()
	smallData := []byte("test") // 4 bytes

	result := reflex.ApplyMorphing(smallData, config)

	if len(result) < config.MinSize {
		t.Errorf("result too small: got %d, want >= %d", len(result), config.MinSize)
	}
	if !hasPrefix(result, smallData) {
		t.Error("result should contain original data")
	}
}

func TestApplyMorphingLargePacket(t *testing.T) {
	config := reflex.DefaultMorphingConfig()
	largeData := make([]byte, 2000) // Larger than MaxSize

	result := reflex.ApplyMorphing(largeData, config)

	if len(result) != len(largeData) {
		t.Error("large packets should not be modified")
	}
}

func TestApplyMorphingRandomization(t *testing.T) {
	config := reflex.DefaultMorphingConfig()
	mediumData := make([]byte, 100) // Between MinSize and MaxSize

	results := make(map[int]bool)
	for i := 0; i < 10; i++ {
		result := reflex.ApplyMorphing(mediumData, config)
		results[len(result)] = true
	}

	// Should have some variation in sizes
	if len(results) == 1 {
		t.Error("randomization should produce varying sizes")
	}
}

func TestValidatePacketSize(t *testing.T) {
	config := reflex.DefaultMorphingConfig()

	if !reflex.ValidatePacketSize(100, config) {
		t.Error("valid size should pass")
	}

	if !reflex.ValidatePacketSize(config.MinSize, config) {
		t.Error("min size should pass")
	}

	if !reflex.ValidatePacketSize(config.MaxSize, config) {
		t.Error("max size should pass")
	}

	if reflex.ValidatePacketSize(config.MinSize-1, config) {
		t.Error("too small size should fail")
	}

	if reflex.ValidatePacketSize(config.MaxSize+1, config) {
		t.Error("too large size should fail")
	}
}

func TestValidatePacketSizeDisabled(t *testing.T) {
	config := &reflex.MorphingConfig{Enabled: false}

	if !reflex.ValidatePacketSize(10, config) {
		t.Error("validation should pass when disabled")
	}

	if !reflex.ValidatePacketSize(10000, config) {
		t.Error("validation should pass when disabled")
	}
}

func hasPrefix(s, prefix []byte) bool {
	if len(s) < len(prefix) {
		return false
	}
	for i := range prefix {
		if s[i] != prefix[i] {
			return false
		}
	}
	return true
}
