package inbound

import (
	"bytes"
	"fmt"
)

func ExampleNewSession() {
	key := bytes.Repeat([]byte{0x33}, 32)
	sess, err := NewSession(key)
	fmt.Println(err == nil && sess != nil)
	// Output: true
}

func ExampleSession_WriteFrame() {
	key := bytes.Repeat([]byte{0x44}, 32)
	sess, err := NewSession(key)
	if err != nil {
		fmt.Println(false)
		return
	}

	var wire bytes.Buffer
	if err := sess.WriteFrame(&wire, FrameTypeData, []byte("hello")); err != nil {
		fmt.Println(false)
		return
	}
	frame, err := sess.ReadFrame(bytes.NewReader(wire.Bytes()))
	fmt.Println(err == nil && string(frame.Payload) == "hello")
	// Output: true
}

