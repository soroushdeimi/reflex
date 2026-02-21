package reflex

// FallbackHandler interface for future fallback server integration
type FallbackHandler interface {
	// ShouldFallback determines if connection should be forwarded to fallback server
	ShouldFallback(peeked []byte) bool
	
	// HandleFallback forwards connection to fallback server
	// This will be implemented in full fallback feature
	HandleFallback(reader interface{}, conn interface{}) error
}

// FallbackDetector provides hooks for fallback detection
type FallbackDetector struct {
	enabled bool
}

// NewFallbackDetector creates a new fallback detector
func NewFallbackDetector(enabled bool) *FallbackDetector {
	return &FallbackDetector{
		enabled: enabled,
	}
}

// IsReflexProtocol checks if peeked data matches Reflex protocol
func (fd *FallbackDetector) IsReflexProtocol(peeked []byte) bool {
	if len(peeked) < 4 {
		return false
	}

	// Check magic number
	magic := uint32(peeked[0])<<24 | uint32(peeked[1])<<16 | uint32(peeked[2])<<8 | uint32(peeked[3])
	return magic == ReflexMagic
}

// ShouldFallback determines if fallback should be used
func (fd *FallbackDetector) ShouldFallback(peeked []byte) bool {
	if !fd.enabled {
		return false
	}
	return !fd.IsReflexProtocol(peeked)
}
