package crypto

import (
	"bytes"
	"testing"
)

func TestRandBytes_LengthAndUniqueness(t *testing.T) {
	t.Parallel()

	const n = 64
	a, err := RandBytes(n)
	if err != nil {
		t.Fatalf("RandBytes: %v", err)
	}
	if len(a) != n {
		t.Fatalf("len=%d, want=%d", len(a), n)
	}
	b, err := RandBytes(n)
	if err != nil {
		t.Fatalf("RandBytes(2): %v", err)
	}
	if bytes.Equal(a, b) {
		t.Fatalf("two subsequent RandBytes(%d) are equal — looks non-random", n)
	}

	zero := make([]byte, n)
	if bytes.Equal(a, zero) {
		t.Fatalf("RandBytes returned all zeros")
	}
}

func TestHashPassword_DeterministicOnSameInput(t *testing.T) {
	t.Parallel()

	pw := []byte("p@ssw0rd")
	salt := []byte("NaCl-16-bytes?")

	h1 := HashPassword(pw, salt)
	h2 := HashPassword(pw, salt)

	if len(h1) == 0 || len(h2) == 0 {
		t.Fatalf("empty hash")
	}
	if !bytes.Equal(h1, h2) {
		t.Fatalf("hash not deterministic for same input")
	}

	h3 := HashPassword(pw, []byte("another-salt----"))
	if bytes.Equal(h1, h3) {
		t.Fatalf("hash should differ when salt differs")
	}

	h4 := HashPassword([]byte("p@ssw0rd!"), salt)
	if bytes.Equal(h1, h4) {
		t.Fatalf("hash should differ when password differs")
	}
}

func TestVerifyPassword(t *testing.T) {
	t.Parallel()

	pw := []byte("correct horse battery staple")
	salt := []byte("salty-salt-123456")

	hash := HashPassword(pw, salt)

	if !VerifyPassword(pw, salt, hash) {
		t.Fatalf("VerifyPassword: expected true for correct password")
	}
	if VerifyPassword([]byte("wrong"), salt, hash) {
		t.Fatalf("VerifyPassword: expected false for wrong password")
	}
	if VerifyPassword(pw, []byte("wrong-salt"), hash) {
		t.Fatalf("VerifyPassword: expected false for wrong salt")
	}
	if VerifyPassword([]byte{}, salt, hash) {
		t.Fatalf("VerifyPassword: expected false for empty password")
	}
}
