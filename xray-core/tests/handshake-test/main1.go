package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/curve25519"
)

type ClientHandshake struct {
	PublicKey [32]byte
	UserID    [16]byte
	Timestamp int64
	Nonce     [16]byte
}

type ServerHandshake struct {
	PublicKey [32]byte
}

func generateKeyPair() (privateKey, publicKey [32]byte) {
	rand.Read(privateKey[:])
	curve25519.ScalarBaseMult(&publicKey, &privateKey)
	return
}

func deriveSharedKey(privateKey, peerPublicKey [32]byte) [32]byte {
	var shared [32]byte
	curve25519.ScalarMult(&shared, &privateKey, &peerPublicKey)
	return shared
}

func deriveSessionKey(sharedKey [32]byte, salt []byte) []byte {
	h := sha256.New()
	h.Write(sharedKey[:])
	h.Write(salt)
	return h.Sum(nil)
}

func authenticateUser(userID [16]byte, allowedUUID string) bool {
	return uuid.UUID(userID).String() == allowedUUID
}

func main() {

	fmt.Println("==== STEP 2 HANDSHAKE TEST START ====")

	clientPriv, clientPub := generateKeyPair()

	clientUUID := uuid.New()
	var userID [16]byte
	copy(userID[:], clientUUID[:])

	var nonce [16]byte
	rand.Read(nonce[:])

	clientHandshake := ClientHandshake{
		PublicKey: clientPub,
		UserID:    userID,
		Timestamp: time.Now().Unix(),
		Nonce:     nonce,
	}

	fmt.Println("Client UUID:", clientUUID.String())

	serverPriv, serverPub := generateKeyPair()

	sharedFromClient := deriveSharedKey(clientPriv, serverPub)
	sharedFromServer := deriveSharedKey(serverPriv, clientHandshake.PublicKey)

	fmt.Println("Shared keys match:",
		hex.EncodeToString(sharedFromClient[:]) ==
			hex.EncodeToString(sharedFromServer[:]))

	sessionKey := deriveSessionKey(sharedFromServer, []byte("reflex-session"))

	fmt.Println("Session key:", hex.EncodeToString(sessionKey))

	authOK := authenticateUser(clientHandshake.UserID, "00000000-0000-0000-0000-000000000000")

	fmt.Println("Authentication success:", authOK)

	fmt.Println("==== TEST COMPLETE ====")
	if !authOK {
		fmt.Println("HTTP/1.1 403 Forbidden")
		fmt.Println("Connection: close")
		fmt.Println()
		fmt.Println("Forbidden")
		return
	}
}
