package reflex_test

import (
	"fmt"
	"io"
	"time"
	
	"github.com/xtls/xray-core/proxy/reflex"
)

// ExampleNewSession demonstrates how to create a secure session for communication.
func ExampleNewSession() {
	key := make([]byte, 32) // Key must be exactly 32 bytes
	session, err := reflex.NewSession(key)
	if err != nil {
		return
	}
	fmt.Printf("Session initialized: %v\n", session != nil)
	// Output: Session initialized: true
}

// ExampleSession_WriteFrameWithMorphing shows how to use traffic shaping.
func ExampleSession_WriteFrameWithMorphing() {
	key := make([]byte, 32)
	session, _ := reflex.NewSession(key)
	
	// We use the YouTube profile to hide our traffic pattern.
	profile := &reflex.YouTubeProfile
	data := []byte("secret data")
	
	// io.Discard is used here for demonstration purposes
	err := session.WriteFrameWithMorphing(io.Discard, reflex.FrameTypeData, data, profile)
	if err == nil {
		fmt.Println("Frame sent with YouTube shape")
	}
	// Output: Frame sent with YouTube shape
}

// ExampleNewDynamicMorpher shows the usage of the advanced profile rotation bonus.
func ExampleNewDynamicMorpher() {
	// Rotate between YouTube and Zoom every 5 seconds
	morpher := reflex.NewDynamicMorpher(5 * time.Second)
	
	profile := morpher.GetCurrentProfile()
	fmt.Printf("Current active profile: %s\n", profile.Name)
	// Output: Current active profile: YouTube
}