package reflex_test

import (
	"fmt"
	"github.com/xtls/xray-core/proxy/reflex"
)

func ExampleGenerateKeyPair() {
	priv, pub, err := reflex.GenerateKeyPair()
	if err != nil {
		panic(err)
	}
	fmt.Printf("Generated keys of length %d and %d\n", len(priv), len(pub))
	// Output: Generated keys of length 32 and 32
}

func ExampleDeriveSharedKey() {
	clientPriv, clientPub, _ := reflex.GenerateKeyPair()
	serverPriv, serverPub, _ := reflex.GenerateKeyPair()

	clientShared := reflex.DeriveSharedKey(clientPriv, serverPub)
	serverShared := reflex.DeriveSharedKey(serverPriv, clientPub)

	if clientShared == serverShared {
		fmt.Println("Shared keys match")
	}
	// Output: Shared keys match
}

func ExampleNewSession() {
	key := make([]byte, 32)
	session, err := reflex.NewSession(key, key)
	if err != nil {
		panic(err)
	}
	_ = session
	fmt.Println("Session created successfully")
	// Output: Session created successfully
}
