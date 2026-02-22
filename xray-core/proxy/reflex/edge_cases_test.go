package reflex

import (
	"bytes"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/reflex/encoding"
)

// TestEmptyHandshakeData tests handling of empty handshake data
func TestEmptyHandshakeData(t *testing.T) {
	emptyData := []byte{}
	_, err := encoding.DecodeClientHandshake(emptyData)
	if err == nil {
		t.Fatal("should return error for empty handshake")
	}
}

// TestTruncatedHandshakeData tests handling of incomplete handshake
func TestTruncatedHandshakeData(t *testing.T) {
	// Only magic number, no rest
	truncated := []byte{0x52, 0x46, 0x58, 0x4C}
	_, err := encoding.DecodeClientHandshake(truncated)
	if err == nil {
		t.Fatal("should return error for truncated handshake")
	}
}

// TestMalformedHandshakeData tests handling of corrupted handshake
func TestMalformedHandshakeData(t *testing.T) {
	malformed := []byte("completely invalid data that is not a handshake at all")
	_, err := encoding.DecodeClientHandshake(malformed)
	if err == nil {
		t.Fatal("should return error for malformed handshake")
	}
}

// TestWrongMagicNumber tests rejection of wrong magic number
func TestWrongMagicNumber(t *testing.T) {
	wrongMagic := []byte{0xFF, 0xFF, 0xFF, 0xFF}
	wrongMagic = append(wrongMagic, make([]byte, 72)...)
	_, err := encoding.DecodeClientHandshake(wrongMagic)
	if err == nil {
		t.Fatal("should reject wrong magic number")
	}
}

// TestZeroTimestamp tests handling of zero timestamp
func TestZeroTimestamp(t *testing.T) {
	zeroTS := int64(0)
	// Zero timestamp is very old, should be rejected
	if encoding.ValidateTimestamp(zeroTS) {
		t.Fatal("zero timestamp should be rejected")
	}
}

// TestNegativeTimestamp tests handling of negative timestamp
func TestNegativeTimestamp(t *testing.T) {
	negativeTS := int64(-1000)
	if encoding.ValidateTimestamp(negativeTS) {
		t.Fatal("negative timestamp should be rejected")
	}
}

// TestExtremeFutureTimestamp tests handling of far future timestamp
func TestExtremeFutureTimestamp(t *testing.T) {
	now := time.Now().Unix()
	farFuture := now + 10000 // 10000 seconds in future
	if encoding.ValidateTimestamp(farFuture) {
		t.Fatal("far future timestamp should be rejected")
	}
}

// TestZeroNonce tests frame with zero nonce
func TestZeroNonce(t *testing.T) {
	var sessionKey [32]byte
	encoder, _ := encoding.NewFrameEncoder(sessionKey[:])
	decoder, _ := encoding.NewFrameDecoder(sessionKey[:])

	// Frame with data
	frame := &encoding.Frame{
		Type:    encoding.FrameTypeData,
		Payload: []byte("test"),
	}

	encoded, err := encoder.Encode(frame)
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}
	decoded, err := decoder.Decode(encoded)

	if err != nil {
		t.Fatalf("should handle frame encryption: %v", err)
	}
	if !bytes.Equal(decoded.Payload, []byte("test")) {
		t.Fatal("payload mismatch")
	}
}

// TestFrameWithZeroPayload tests empty frame
func TestFrameWithZeroPayload(t *testing.T) {
	var sessionKey [32]byte
	encoder, _ := encoding.NewFrameEncoder(sessionKey[:])
	decoder, _ := encoding.NewFrameDecoder(sessionKey[:])

	frame := &encoding.Frame{
		Type:    encoding.FrameTypeData,
		Payload: []byte{},
	}

	encoded, err := encoder.Encode(frame)
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}
	decoded, err := decoder.Decode(encoded)

	if err != nil {
		t.Fatalf("should handle empty payload: %v", err)
	}
	if len(decoded.Payload) != 0 {
		t.Fatal("payload should be empty")
	}
}

// TestSingleBytePayload tests minimal payload
func TestSingleBytePayload(t *testing.T) {
	var sessionKey [32]byte
	encoder, _ := encoding.NewFrameEncoder(sessionKey[:])
	decoder, _ := encoding.NewFrameDecoder(sessionKey[:])

	frame := &encoding.Frame{
		Type:    encoding.FrameTypeData,
		Payload: []byte{0xAB},
	}

	encoded, err := encoder.Encode(frame)
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}
	decoded, _ := decoder.Decode(encoded)

	if !bytes.Equal(decoded.Payload, []byte{0xAB}) {
		t.Fatal("single byte payload mismatch")
	}
}

// TestMaxFrameSize tests frame at maximum size
func TestMaxFrameSize(t *testing.T) {
	var sessionKey [32]byte
	encoder, _ := encoding.NewFrameEncoder(sessionKey[:])
	decoder, _ := encoding.NewFrameDecoder(sessionKey[:])

	// Max payload size
	maxPayload := make([]byte, encoding.MaxFramePayloadSize)
	for i := 0; i < len(maxPayload); i++ {
		maxPayload[i] = byte(i % 256)
	}

	frame := &encoding.Frame{
		Type:    encoding.FrameTypeData,
		Payload: maxPayload,
	}

	encoded, err := encoder.Encode(frame)
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}
	decoded, err := decoder.Decode(encoded)

	if err != nil {
		t.Fatalf("should handle max size: %v", err)
	}
	if !bytes.Equal(decoded.Payload, maxPayload) {
		t.Fatal("max payload mismatch")
	}
}

// TestFrameOversizePayload tests payload exceeding max
func TestFrameOversizePayload(t *testing.T) {
	var sessionKey [32]byte
	encoder, _ := encoding.NewFrameEncoder(sessionKey[:])

	// Payload larger than max
	hugePayload := make([]byte, encoding.MaxFramePayloadSize+1000)
	for i := 0; i < len(hugePayload); i++ {
		hugePayload[i] = byte(i % 256)
	}

	frame := &encoding.Frame{
		Type:    encoding.FrameTypeData,
		Payload: hugePayload,
	}

	// Encoder should either split or handle gracefully
	encoded, err := encoder.Encode(frame)
	if err != nil {
		// May error or truncate - both are valid
		return
	}
	if len(encoded) == 0 {
		t.Fatal("encoder should handle oversized payload")
	}
}

// TestInvalidSessionKey tests with invalid encryption key
func TestInvalidSessionKey(t *testing.T) {
	// Empty key
	_, err := encoding.NewFrameEncoder([]byte{})
	if err == nil {
		t.Fatal("should reject empty key")
	}

	// Too short key
	shortKey := make([]byte, 10)
	_, err = encoding.NewFrameEncoder(shortKey)
	if err == nil {
		t.Fatal("should reject short key")
	}
}

// TestWrongKeyDecryption tests decryption with different key
func TestWrongKeyDecryption(t *testing.T) {
	var key1, key2 [32]byte
	for i := 0; i < 32; i++ {
		key1[i] = byte(i)
		key2[i] = byte(255 - i)
	}

	encoder, _ := encoding.NewFrameEncoder(key1[:])
	decoderWrongKey, _ := encoding.NewFrameDecoder(key2[:])

	frame := &encoding.Frame{
		Type:    encoding.FrameTypeData,
		Payload: []byte("secret"),
	}

	encoded, err := encoder.Encode(frame)
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	// Decoding with wrong key should fail
	_, err = decoderWrongKey.Decode(encoded)
	if err == nil {
		t.Fatal("should fail with wrong key")
	}
}

// TestCorruptedCiphertext tests tampering detection
func TestCorruptedCiphertext(t *testing.T) {
	var sessionKey [32]byte
	encoder, _ := encoding.NewFrameEncoder(sessionKey[:])
	decoder, _ := encoding.NewFrameDecoder(sessionKey[:])

	frame := &encoding.Frame{
		Type:    encoding.FrameTypeData,
		Payload: []byte("message"),
	}

	encoded, err := encoder.Encode(frame)
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	// Corrupt a byte
	if len(encoded) > 10 {
		encoded[10] ^= 0xFF
	}

	// Should fail authentication
	_, err = decoder.Decode(encoded)
	if err == nil {
		t.Fatal("should detect corruption")
	}
}

// TestValidatorEmptyDatabase tests validator with no users
func TestValidatorEmptyDatabase(t *testing.T) {
	validator := &Validator{
		users: make(map[[16]byte]*protocol.MemoryUser),
	}

	var anyUUID [16]byte
	user, err := validator.Get(anyUUID)
	if err == nil {
		t.Fatal("empty validator should return error")
	}
	if user != nil {
		t.Fatal("empty validator should return nil user")
	}
}

// TestValidatorWithZeroUUID tests lookup with all-zero UUID
func TestValidatorWithZeroUUID(t *testing.T) {
	validator := &Validator{
		users: make(map[[16]byte]*protocol.MemoryUser),
	}

	id, _ := uuid.ParseString("00000000-0000-0000-0000-000000000000")
	user := &protocol.MemoryUser{
		Account: &MemoryAccount{ID: protocol.NewID(id)},
		Email:   "zero@example.com",
	}
	validator.Add(user)

	// Lookup with zero UUID
	var zeroArray [16]byte
	retrieved, err := validator.Get(zeroArray)
	if err != nil {
		t.Fatalf("should find user with zero UUID: %v", err)
	}
	if retrieved == nil {
		t.Fatal("should find user with zero UUID")
	}
}

// TestValidatorWithAllFFUUID tests lookup with all-FF UUID
func TestValidatorWithAllFFUUID(t *testing.T) {
	validator := &Validator{
		users: make(map[[16]byte]*protocol.MemoryUser),
	}

	id, _ := uuid.ParseString("ffffffff-ffff-ffff-ffff-ffffffffffff")
	user := &protocol.MemoryUser{
		Account: &MemoryAccount{ID: protocol.NewID(id)},
		Email:   "ff@example.com",
	}
	validator.Add(user)

	// Lookup with all-FF UUID
	var ffArray [16]byte
	for i := 0; i < 16; i++ {
		ffArray[i] = 0xFF
	}
	retrieved, err := validator.Get(ffArray)
	if err != nil {
		t.Fatalf("should find user with all-FF UUID: %v", err)
	}
	if retrieved == nil {
		t.Fatal("should find user with all-FF UUID")
	}
}

// TestValidatorRemoveWithEmptyEmail tests remove with empty email
func TestValidatorRemoveWithEmptyEmail(t *testing.T) {
	validator := &Validator{
		users: make(map[[16]byte]*protocol.MemoryUser),
	}

	err := validator.Remove("")
	if err == nil {
		t.Fatal("should return error for empty email")
	}
}

// TestFrameTypeInvalid tests handling of unknown frame type
func TestFrameTypeInvalid(t *testing.T) {
	var sessionKey [32]byte
	encoder, _ := encoding.NewFrameEncoder(sessionKey[:])
	decoder, _ := encoding.NewFrameDecoder(sessionKey[:])

	// Invalid frame type (0xFF)
	frame := &encoding.Frame{
		Type:    0xFF,
		Payload: []byte("data"),
	}

	encoded, err := encoder.Encode(frame)
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}
	decoded, err := decoder.Decode(encoded)

	// Should still work - frame type is just data
	if err != nil {
		t.Fatalf("should handle unknown frame type: %v", err)
	}
	if decoded.Type != 0xFF {
		t.Fatal("frame type should be preserved")
	}
}

// TestSharedSecretConsistency tests ECDH consistency
func TestSharedSecretConsistency(t *testing.T) {
	alicePriv, _, _ := encoding.GenerateKeyPair()
	_, bobPub, _ := encoding.GenerateKeyPair()

	// Multiple calls should produce same shared secret
	shared1 := encoding.DeriveSharedKey(alicePriv, bobPub)
	shared2 := encoding.DeriveSharedKey(alicePriv, bobPub)

	if !bytes.Equal(shared1[:], shared2[:]) {
		t.Fatal("repeated key derivation should be consistent")
	}

	// But different key pairs should produce different secrets
	_, charliePub, _ := encoding.GenerateKeyPair()
	shared3 := encoding.DeriveSharedKey(alicePriv, charliePub)

	if bytes.Equal(shared1[:], shared3[:]) {
		t.Fatal("different key pairs should produce different secrets")
	}
}

// TestSessionKeyConsistency tests HKDF consistency
func TestSessionKeyConsistency(t *testing.T) {
	var sharedKey [32]byte
	for i := 0; i < 32; i++ {
		sharedKey[i] = byte(i)
	}

	salt := []byte("salt")

	key1, _ := encoding.DeriveSessionKey(sharedKey, salt)
	key2, _ := encoding.DeriveSessionKey(sharedKey, salt)

	if !bytes.Equal(key1, key2) {
		t.Fatal("repeated key derivation should be consistent")
	}
}

// TestAccountWithLongEmail tests account with very long email
func TestAccountWithLongEmail(t *testing.T) {
	id, _ := uuid.ParseString("b831381d-6324-4d53-ad4f-8cda48b30811")

	longEmail := ""
	for i := 0; i < 1000; i++ {
		longEmail += "a"
	}
	longEmail += "@example.com"

	user := &protocol.MemoryUser{
		Account: &MemoryAccount{ID: protocol.NewID(id)},
		Email:   longEmail,
	}

	validator := &Validator{
		users: make(map[[16]byte]*protocol.MemoryUser),
	}

	err := validator.Add(user)
	if err != nil {
		t.Fatalf("should handle long email: %v", err)
	}
}

// TestAccountWithSpecialCharacters tests account with special characters
func TestAccountWithSpecialCharacters(t *testing.T) {
	id, _ := uuid.ParseString("b831381d-6324-4d53-ad4f-8cda48b30811")

	specialEmails := []string{
		"user+tag@example.com",
		"user.name@example.co.uk",
		"user_name@example.com",
		"user-name@example.com",
		"123@example.com",
	}

	validator := &Validator{
		users: make(map[[16]byte]*protocol.MemoryUser),
	}

	for _, email := range specialEmails {
		user := &protocol.MemoryUser{
			Account: &MemoryAccount{ID: protocol.NewID(id)},
			Email:   email,
		}
		err := validator.Add(user)
		if err != nil {
			t.Fatalf("should handle special email '%s': %v", email, err)
		}
	}
}

// TestSequenceCounterOverflow tests frame counter behavior
func TestSequenceCounterOverflow(t *testing.T) {
	var sessionKey [32]byte
	encoder, _ := encoding.NewFrameEncoder(sessionKey[:])
	decoder, _ := encoding.NewFrameDecoder(sessionKey[:])

	// Send many frames to test counter
	for i := 0; i < 1000; i++ {
		frame := &encoding.Frame{
			Type:    encoding.FrameTypeData,
			Payload: []byte{byte(i)},
		}

		encoded, err := encoder.Encode(frame)
		if err != nil {
			t.Fatalf("frame %d encode failed: %v", i, err)
		}
		decoded, err := decoder.Decode(encoded)

		if err != nil {
			t.Fatalf("frame %d failed: %v", i, err)
		}
		if decoded.Payload[0] != byte(i) {
			t.Fatalf("frame %d payload mismatch", i)
		}
	}
}

// TestBoundaryTimestamps tests timestamp validation boundaries
func TestBoundaryTimestamps(t *testing.T) {
	now := time.Now().Unix()

	tests := []struct {
		offset   int64
		expected bool
	}{
		{-120, true},   // Exactly at lower boundary
		{-121, false},  // Just beyond lower boundary
		{120, true},    // Positive buffer
		{121, false},   // Beyond positive buffer
		{0, true},      // Now
	}

	for _, tt := range tests {
		ts := now + tt.offset
		result := encoding.ValidateTimestamp(ts)
		if result != tt.expected {
			t.Fatalf("offset %d: expected %v, got %v", tt.offset, tt.expected, result)
		}
	}
}
