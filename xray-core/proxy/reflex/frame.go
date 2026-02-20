package reflex

import (
	"encoding/binary"
	"io"
)

// Frame types
const (
	FrameTypeData    = 0x01
	FrameTypePadding = 0x02
	FrameTypeTiming  = 0x03
	FrameTypeClose   = 0x04
)

// Frame represents a Reflex protocol frame
type Frame struct {
	Length  uint16
	Type    uint8
	Payload []byte
}

// ReadFrameHeader reads frame header (3 bytes: length + type)
func ReadFrameHeader(reader io.Reader) (length uint16, frameType uint8, err error) {
	header := make([]byte, 3)
	if _, err = io.ReadFull(reader, header); err != nil {
		return 0, 0, newError("failed to read frame header").Base(err)
	}

	length = binary.BigEndian.Uint16(header[0:2])
	frameType = header[2]
	return
}

// WriteFrameHeader writes frame header
func WriteFrameHeader(writer io.Writer, length uint16, frameType uint8) error {
	header := make([]byte, 3)
	binary.BigEndian.PutUint16(header[0:2], length)
	header[2] = frameType

	if _, err := writer.Write(header); err != nil {
		return newError("failed to write frame header").Base(err)
	}
	return nil
}

// ValidateFrameType checks if frame type is valid
func ValidateFrameType(frameType uint8) bool {
	return frameType >= FrameTypeData && frameType <= FrameTypeClose
}
