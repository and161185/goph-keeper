// Package clientcrypto contains client-side primitives for key wrapping and AEAD.
package clientcrypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// Params
const (
	DEKLen = 32
	KeKLen = 32

	argonTime    uint32 = 3
	argonMemory  uint32 = 64 * 1024
	argonThreads uint8  = 1
)

func Rand(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}

// DeriveKEK derives a KEK from password and kekSalt using Argon2id.
func DeriveKEK(password, kekSalt []byte) []byte {
	return argon2.IDKey(password, kekSalt, argonTime, argonMemory, argonThreads, KeKLen)
}

// WrapDEK encrypts DEK with KEK using XChaCha20-Poly1305 and random nonce.
func WrapDEK(kek, dek []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(kek)
	if err != nil {
		return nil, err
	}
	nonce, err := Rand(chacha20poly1305.NonceSizeX)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(nonce)+len(dek)+aead.Overhead())
	out = append(out, nonce...)
	out = append(out, aead.Seal(nil, nonce, dek, nil)...)
	return out, nil
}

// UnwrapDEK decrypts wrapped DEK using KEK.
func UnwrapDEK(kek, wrapped []byte) ([]byte, error) {
	if len(wrapped) < chacha20poly1305.NonceSizeX {
		return nil, errors.New("wrapped too short")
	}
	aead, err := chacha20poly1305.NewX(kek)
	if err != nil {
		return nil, err
	}
	nonce := wrapped[:chacha20poly1305.NonceSizeX]
	ct := wrapped[chacha20poly1305.NonceSizeX:]
	return aead.Open(nil, nonce, ct, nil)
}

// DeriveItemKey derives a per-item key via HKDF-SHA256 using itemID as info.
func DeriveItemKey(dek, itemID []byte) ([]byte, error) {
	r := hkdf.New(sha256.New, dek, nil, itemID)
	key := make([]byte, DEKLen)
	_, err := r.Read(key)
	return key, err
}

// EncryptBlob encrypts plaintext with AAD = userID||itemID||ver and random nonce.
func EncryptBlob(key, userID, itemID []byte, ver int64, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce, err := Rand(chacha20poly1305.NonceSizeX)
	if err != nil {
		return nil, err
	}
	aad := make([]byte, 0, len(userID)+len(itemID)+8)
	aad = append(aad, userID...)
	aad = append(aad, itemID...)
	var v [8]byte
	binary.BigEndian.PutUint64(v[:], uint64(ver))
	aad = append(aad, v[:]...)
	out := make([]byte, 0, len(nonce)+len(plaintext)+aead.Overhead())
	out = append(out, nonce...)
	out = append(out, aead.Seal(nil, nonce, plaintext, aad)...)
	return out, nil
}

// DecryptBlob decrypts a blob using the same AAD as during encryption.
func DecryptBlob(key, userID, itemID []byte, ver int64, blob []byte) ([]byte, error) {
	if len(blob) < chacha20poly1305.NonceSizeX {
		return nil, errors.New("blob too short")
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := blob[:chacha20poly1305.NonceSizeX]
	ct := blob[chacha20poly1305.NonceSizeX:]
	aad := make([]byte, 0, len(userID)+len(itemID)+8)
	aad = append(aad, userID...)
	aad = append(aad, itemID...)
	var v [8]byte
	binary.BigEndian.PutUint64(v[:], uint64(ver))
	aad = append(aad, v[:]...)
	return aead.Open(nil, nonce, ct, aad)
}
