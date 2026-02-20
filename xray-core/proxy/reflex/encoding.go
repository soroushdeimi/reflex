package reflex

/*
// import (
// 	"encoding/binary"
// 	"io"
// 	"math/rand"
// 	"time"
// )

/*
func (s *Session) WriteFrameWithMorphing(writer io.Writer, frameType uint8, data []byte, profile *TrafficProfile) error {
	if profile == nil {
		return s.WriteFrame(writer, frameType, data)
	}

	targetSize := profile.GetSize()
	
	// If data is too large, we split it recursively
	maxPayloadSize := targetSize
	if maxPayloadSize > 16384 {
		maxPayloadSize = 16384
	}
	
	if len(data) > maxPayloadSize {
		chunk := data[:maxPayloadSize]
		remaining := data[maxPayloadSize:]
		if err := s.writeFrameChunk(writer, frameType, chunk, profile); err != nil {
			return err
		}
		return s.WriteFrameWithMorphing(writer, frameType, remaining, profile)
	}

	// Apply padding if needed (simplified: just send as is for now if smaller)
	// Or we could pad. The morphing logic implies padding.
	
	header := make([]byte, 3)
	binary.BigEndian.PutUint16(header[0:2], uint16(len(data)))
	header[2] = frameType

	nonce := make([]byte, 12)
	binary.LittleEndian.PutUint64(nonce[4:12], s.WriteNonce)
	s.WriteNonce++

	encrypted := s.AEAD.Seal(nil, nonce, data, header)

	if _, err := writer.Write(header); err != nil {
		return err
	}
	if _, err := writer.Write(encrypted); err != nil {
		return err
	}

	delay := profile.GetDelay()
	time.Sleep(delay)

	return nil
}

func (s *Session) writeFrameChunk(writer io.Writer, frameType uint8, data []byte, profile *TrafficProfile) error {
	return s.WriteFrameWithMorphing(writer, frameType, data, profile)
}

func (s *Session) HandleControlFrame(frame *Frame, profile *TrafficProfile) {
	if profile == nil {
		return
	}
	switch frame.Type {
	case FrameTypePadding:
		if len(frame.Payload) >= 2 {
			targetSize := int(binary.BigEndian.Uint16(frame.Payload))
			profile.SetNextPacketSize(targetSize)
		}
	case FrameTypeTiming:
		if len(frame.Payload) >= 8 {
			delayMs := binary.BigEndian.Uint64(frame.Payload)
			profile.SetNextDelay(time.Duration(delayMs) * time.Millisecond)
		}
	}
}
*/
