package encoding

import (
  "encoding/binary"
  "errors"
  "io"
)

// Frame: represents a Reflex protocol frame
type Frame struct {
    Length  uint16
    Type    uint8
    Payload []byte
}

const (
    FrameTypeData =    0x01
    FrameTypePadding = 0x02
    FrameTypeTiming =  0x03
    FrameTypeClose =   0x04
)

//  ReadFrame: reads and decrypts a frame from the reader
func (s *Session) ReadFrame(r io.Reader) (*Frame, error) {
    // read frame header
    header := make([]byte, 3)
    if _, err := io.ReadFull(r, header); err != nil {
        return nil, err
    }

    frameType := header[0]
    encPayloadLen := binary.BigEndian.Uint16(header[1:3])

    // read encrypted payload
    encPayload := make([]byte, encPayloadLen)
    if _, err := io.ReadFull(r, encPayload); err != nil {
        return nil, err
    }

    // decrypt the payload
    nonce := makeNonce(s.readNonce)
    s.readNonce++

    payload, err := s.aead.Open(nil, nonce[:], encPayload, nil)
    if err != nil {
        return nil, errors.New("failed to decrypt frame: possible corruption or replay attack")
    }

    return &Frame{
        Length:  encPayloadLen,
        Type:    frameType,
        Payload: payload,
    }, nil
}
