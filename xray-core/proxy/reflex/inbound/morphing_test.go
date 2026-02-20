package inbound

import (
	"bytes"
	"testing"
	"time"
)

func TestProfileSizeSelection(t *testing.T) {
	prof := DefaultProfile
	if prof == nil {
		t.Fatal("Missing default profile")
	}

	for k := 0; k < 50; k++ {
		if res := prof.GetPacketSize(); res <= 0 {
			t.Fatalf("Invalid size generated: %d", res)
		}
	}

	prof.SetNextPacketSize(999)
	if prof.GetPacketSize() != 999 {
		t.Error("Manual size override failed")
	}

	_ = prof.GetPacketSize()
}

func TestProfileDelaySelection(t *testing.T) {
	prof := DefaultProfile

	for k := 0; k < 20; k++ {
		if res := prof.GetDelay(); res < 0 {
			t.Fatalf("Negative delay generated: %v", res)
		}
	}

	target := 100 * time.Millisecond
	prof.SetNextDelay(target)
	if prof.GetDelay() != target {
		t.Error("Manual delay override failed")
	}
}

func TestTrafficPaddingLogic(t *testing.T) {
	prof := DefaultProfile
	sample := []byte("short")

	padded, wait := prof.ApplyMorphing(sample)
	if len(padded) < len(sample) {
		t.Fatalf("Padding shortened the payload. Got len %d", len(padded))
	}
	if wait < 0 {
		t.Fatalf("Invalid morphing delay: %v", wait)
	}

	var emptyProf *TrafficProfile
	raw, zeroWait := emptyProf.ApplyMorphing(sample)
	
	if !bytes.Equal(raw, sample) {
		t.Error("Nil profile mutated the data")
	}
	if zeroWait != 0 {
		t.Error("Nil profile produced non-zero delay")
	}
}