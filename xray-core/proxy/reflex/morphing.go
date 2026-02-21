package reflex

import (
	"crypto/rand"
)

// MorphingConfig controls traffic morphing behavior
type MorphingConfig struct {
	Enabled      bool
	MinSize      int // Minimum packet size after padding
	MaxSize      int // Maximum packet size after padding
	Randomize    bool // Randomize padding size
}

// DefaultMorphingConfig returns default morphing configuration
func DefaultMorphingConfig() *MorphingConfig {
	return &MorphingConfig{
		Enabled:   true,
		MinSize:   64,
		MaxSize:   1500,
		Randomize: true,
	}
}

// ApplyMorphing pads data to target size range
func ApplyMorphing(data []byte, config *MorphingConfig) []byte {
	if config == nil || !config.Enabled {
		return data
	}

	currentSize := len(data)
	targetSize := currentSize

	// Determine target size
	if currentSize < config.MinSize {
		targetSize = config.MinSize
	} else if config.Randomize && currentSize < config.MaxSize {
		// Randomize size between current and max
		rangeSize := config.MaxSize - currentSize
		if rangeSize > 0 {
			randomBytes := make([]byte, 4)
			rand.Read(randomBytes)
			randomOffset := int(randomBytes[0]) % rangeSize
			targetSize = currentSize + randomOffset
		}
	}

	// Apply padding if needed
	if targetSize > currentSize {
		paddingSize := targetSize - currentSize
		padding := make([]byte, paddingSize)
		rand.Read(padding)
		return append(data, padding...)
	}

	return data
}

// ValidatePacketSize checks if packet size is suspicious
func ValidatePacketSize(size int, config *MorphingConfig) bool {
	if config == nil || !config.Enabled {
		return true
	}

	// Drop packets that are too small (potential probe)
	if size > 0 && size < config.MinSize {
		return false
	}

	// Drop packets that are too large (potential attack)
	if size > config.MaxSize {
		return false
	}

	return true
}
