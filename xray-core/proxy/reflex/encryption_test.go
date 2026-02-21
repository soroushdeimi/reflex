package reflex

import (
	"testing"
)

func TestEncryption(t *testing.T) {
	testKey := make([]byte, 32)
	for i := 0; i < 32; i++ {
		testKey[i] = byte(i)
	}

}
