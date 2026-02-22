package reflex

import "testing"

func TestParseUUID_Valid(t *testing.T) {
	s := "550e8400-e29b-41d4-a716-446655440000"

	u, err := ParseUUID(s)
	if err != nil {
		t.Fatalf("ParseUUID err: %v", err)
	}

	got := UUIDString(u)

	if got != s {
		t.Fatalf("UUIDString mismatch: got=%s want=%s", got, s)
	}
}

func TestParseUUID_Invalid(t *testing.T) {
	_, err := ParseUUID("not-a-uuid")
	if err == nil {
		t.Fatalf("expected error for invalid uuid")
	}
}
