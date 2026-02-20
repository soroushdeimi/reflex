package reflex

import (
	"bytes"
	"io"
	"testing"
)

func TestFrameHeaderIO(t *testing.T) {
	// Test data
	length := uint16(512)
	frameType := uint8(FrameTypeData)
	buf := new(bytes.Buffer)

	// Test writing header
	err := WriteFrameHeader(buf, length, frameType)
	if err != nil {
		t.Fatal("failed to write frame header:", err)
	}

	if buf.Len() != 3 {
		t.Errorf("expected 3 bytes, got %d", buf.Len())
	}

	// Test reading header back
	rLen, rType, err := ReadFrameHeader(buf)
	if err != nil {
		t.Fatal("failed to read frame header:", err)
	}

	if rLen != length {
		t.Errorf("expected length %d, got %d", length, rLen)
	}

	if rType != frameType {
		t.Errorf("expected type %d, got %d", frameType, rType)
	}
}

func TestValidateFrameType(t *testing.T) {
	testCases := []struct {
		fType uint8
		valid bool
	}{
		{FrameTypeData, true},
		{FrameTypePadding, true},
		{FrameTypeTiming, true},
		{FrameTypeClose, true},
		{0x00, false},
		{0x05, false},
		{0xFF, false},
	}

	for _, tc := range testCases {
		if ValidateFrameType(tc.fType) != tc.valid {
			t.Errorf("type 0x%x failed validation check", tc.fType)
		}
	}
}

func TestReadFrameHeaderErrors(t *testing.T) {
	// Test short read error
	shortBuf := bytes.NewReader([]byte{0x00, 0x01}) // only 2 bytes
	_, _, err := ReadFrameHeader(shortBuf)
	if err != io.ErrUnexpectedEOF && err == nil {
		t.Error("expected error for incomplete read")
	}
}
