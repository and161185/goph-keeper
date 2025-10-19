// Package crypto implements server-side password hashing and verification.
package crypto

import (
	"crypto/rand"
	"crypto/subtle"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters (tuned for server-side hashing).
const (
	argonTime    uint32 = 3         // iterations
	argonMemory  uint32 = 64 * 1024 // 64 MB
	argonThreads uint8  = 1
	argonKeyLen  uint32 = 32
)

// RandBytes returns n cryptographically secure random bytes.
func RandBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}

// HashPassword returns Argon2id hash of password using the provided salt.
func HashPassword(password, salt []byte) []byte {
	return argon2.IDKey(password, salt, argonTime, argonMemory, argonThreads, argonKeyLen)
}

// VerifyPassword verifies password against expected Argon2id hash and salt.
func VerifyPassword(password, salt, expected []byte) bool {
	got := HashPassword(password, salt)
	return subtle.ConstantTimeCompare(got, expected) == 1
}
