package reflex

import (
	"crypto/rand"
	"io"
	"time"
)

// MorphingWriter wraps a writer with traffic morphing
type MorphingWriter struct {
	writer  io.Writer
	profile *TrafficProfile
	enabled bool
}

// NewMorphingWriter creates new morphing writer
func NewMorphingWriter(writer io.Writer, profile *TrafficProfile) *MorphingWriter {
	if profile == nil {
		profile = GenericProfile
	}
	return &MorphingWriter{
		writer:  writer,
		profile: profile,
		enabled: true,
	}
}

// AddPadding adds random padding to reach target size
func (mw *MorphingWriter) AddPadding(data []byte, targetSize int) []byte {
	if len(data) >= targetSize {
		return data[:targetSize]
	}

	paddingSize := targetSize - len(data)
	padding := make([]byte, paddingSize)
	if _, err := rand.Read(padding); err != nil {
		// Fallback: if rand fails, use zeros
		for i := range padding {
			padding[i] = 0
		}
	}

	return append(data, padding...)
}

// WriteWithMorphing writes data with traffic morphing
func (mw *MorphingWriter) WriteWithMorphing(data []byte) (int, error) {
	if !mw.enabled || mw.profile == nil {
		return mw.writer.Write(data)
	}

	totalWritten := 0

	for len(data) > 0 {
		// Get target packet size from profile
		targetSize := mw.profile.GetPacketSize()

		// Take chunk from data
		var chunk []byte
		if len(data) > targetSize {
			chunk = data[:targetSize]
			data = data[targetSize:]
		} else {
			chunk = data
			data = nil
		}

		// Add padding if needed
		morphed := mw.AddPadding(chunk, targetSize)

		// Write morphed packet
		n, err := mw.writer.Write(morphed)
		totalWritten += n
		if err != nil {
			return totalWritten, err
		}

		// Apply delay from profile
		if len(data) > 0 {
			delay := mw.profile.GetDelay()
			time.Sleep(delay)
		}
	}

	return totalWritten, nil
}

// SetProfile updates traffic profile
func (mw *MorphingWriter) SetProfile(profile *TrafficProfile) {
	mw.profile = profile
}

// SetEnabled enables/disables morphing
func (mw *MorphingWriter) SetEnabled(enabled bool) {
	mw.enabled = enabled
}

// MorphingReader wraps a reader and removes morphing
type MorphingReader struct {
	reader io.Reader
}

// NewMorphingReader creates new morphing reader
func NewMorphingReader(reader io.Reader) *MorphingReader {
	return &MorphingReader{
		reader: reader,
	}
}

// RemovePadding removes random padding from morphed packet
// Note: This is a no-op in practice because padding is transparent
func (mr *MorphingReader) RemovePadding(data []byte) []byte {
	// In actual implementation, we'd need metadata about original size
	// For now, return as-is (padding is handled at Frame level)
	return data
}

// Read reads from underlying reader
func (mr *MorphingReader) Read(p []byte) (int, error) {
	return mr.reader.Read(p)
}
