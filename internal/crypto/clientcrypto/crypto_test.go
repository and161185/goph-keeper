package clientcrypto

import (
	"bytes"
	"crypto/subtle"
	"testing"
)

func TestRand_LengthUniq(t *testing.T) {
	t.Parallel()
	const n = 48
	a, err := Rand(n)
	if err != nil {
		t.Fatalf("Rand: %v", err)
	}
	if len(a) != n {
		t.Fatalf("len=%d, want=%d", len(a), n)
	}
	b, _ := Rand(n)
	if bytes.Equal(a, b) {
		t.Fatalf("Rand produced equal slices")
	}
}

func TestDeriveKEK_DeterministicAndSaltDependent(t *testing.T) {
	t.Parallel()
	pw := []byte("secret-pass")
	s1 := []byte("salt-1")
	s2 := []byte("salt-2")
	k1 := DeriveKEK(pw, s1)
	k2 := DeriveKEK(pw, s1)
	if subtle.ConstantTimeCompare(k1, k2) != 1 {
		t.Fatalf("DeriveKEK not deterministic")
	}
	if subtle.ConstantTimeCompare(k1, DeriveKEK(pw, s2)) != 0 {
		t.Fatalf("DeriveKEK must change with salt")
	}
	if subtle.ConstantTimeCompare(k1, DeriveKEK([]byte("other"), s1)) != 0 {
		t.Fatalf("DeriveKEK must change with password")
	}
}

func TestWrapUnwrapDEK(t *testing.T) {
	t.Parallel()
	kek := DeriveKEK([]byte("pw"), []byte("salt"))
	dek, _ := Rand(32)

	wrapped, err := WrapDEK(kek, dek)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}
	if len(wrapped) == 0 {
		t.Fatalf("wrapped empty")
	}

	out, err := UnwrapDEK(kek, wrapped)
	if err != nil {
		t.Fatalf("UnwrapDEK: %v", err)
	}
	if subtle.ConstantTimeCompare(out, dek) != 1 {
		t.Fatalf("unwrap != original")
	}

	bad := DeriveKEK([]byte("pw2"), []byte("salt"))
	if _, err := UnwrapDEK(bad, wrapped); err == nil {
		t.Fatalf("UnwrapDEK with wrong kek must fail")
	}
}

func TestDeriveItemKey_DiffPerItem(t *testing.T) {
	t.Parallel()
	dek, _ := Rand(32)
	itemA := []byte("item-A")
	itemB := []byte("item-B")
	ka, _ := DeriveItemKey(dek, itemA)
	kb, _ := DeriveItemKey(dek, itemB)

	if len(ka) == 0 || len(kb) == 0 {
		t.Fatalf("empty derived key")
	}
	if subtle.ConstantTimeCompare(ka, kb) != 0 {
		t.Fatalf("keys for different items must differ")
	}
	ka2, _ := DeriveItemKey(dek, itemA)
	if subtle.ConstantTimeCompare(ka, ka2) != 1 {
		t.Fatalf("DeriveItemKey must be deterministic")
	}
}

func TestEncryptDecryptBlob_Roundtrip(t *testing.T) {
	t.Parallel()
	dek, _ := Rand(32)
	itemID := []byte("item-xyz")
	userID := []byte("user-123")
	ver := int64(7)
	key, err := DeriveItemKey(dek, itemID)
	if err != nil {
		t.Fatalf("DeriveItemKey: %v", err)
	}

	pt := []byte("top secret payload \x00\x01\x02")
	blob, err := EncryptBlob(key, userID, itemID, ver, pt)
	if err != nil {
		t.Fatalf("EncryptBlob: %v", err)
	}
	if bytes.Equal(blob, pt) {
		t.Fatalf("ciphertext must differ from plaintext")
	}

	got, err := DecryptBlob(key, userID, itemID, ver, blob)
	if err != nil {
		t.Fatalf("DecryptBlob: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("roundtrip mismatch")
	}
}

func TestDecryptBlob_RejectsAADMismatch(t *testing.T) {
	t.Parallel()
	dek, _ := Rand(32)
	itemID := []byte("item-1")
	userID := []byte("user-1")
	ver := int64(1)
	key, _ := DeriveItemKey(dek, itemID)
	pt := []byte("payload")

	blob, _ := EncryptBlob(key, userID, itemID, ver, pt)

	if _, err := DecryptBlob(key, []byte("user-2"), itemID, ver, blob); err == nil {
		t.Fatalf("expected error on userID mismatch")
	}

	if _, err := DecryptBlob(key, userID, []byte("item-2"), ver, blob); err == nil {
		t.Fatalf("expected error on itemID mismatch")
	}

	if _, err := DecryptBlob(key, userID, itemID, ver+1, blob); err == nil {
		t.Fatalf("expected error on version mismatch")
	}

	key2, _ := DeriveItemKey(dek, []byte("item-OTHER"))
	if _, err := DecryptBlob(key2, userID, itemID, ver, blob); err == nil {
		t.Fatalf("expected error on wrong key")
	}
}

func TestRand_Length_And_Randomness(t *testing.T) {
	a, err := Rand(32)
	if err != nil || len(a) != 32 {
		t.Fatalf("Rand len/err: %d %v", len(a), err)
	}
	b, _ := Rand(32)
	if bytes.Equal(a, b) {
		t.Fatalf("Rand should be random")
	}
}

func TestDeriveKEK_Deterministic(t *testing.T) {
	pw := []byte("password")
	salt := []byte("salt-123")
	k1 := DeriveKEK(pw, salt)
	k2 := DeriveKEK(pw, salt)
	if !bytes.Equal(k1, k2) || len(k1) == 0 {
		t.Fatalf("DeriveKEK not deterministic / empty")
	}
	k3 := DeriveKEK([]byte("other"), salt)
	if bytes.Equal(k1, k3) {
		t.Fatalf("DeriveKEK should change with password")
	}
}

func TestWrap_Unwrap_DEK_Roundtrip(t *testing.T) {
	pw := []byte("pwd")
	salt := []byte("salt")
	kek := DeriveKEK(pw, salt)

	dek, err := Rand(DEKLen)
	if err != nil {
		t.Fatalf("Rand DEK: %v", err)
	}
	w, err := WrapDEK(kek, dek)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}
	out, err := UnwrapDEK(kek, w)
	if err != nil {
		t.Fatalf("UnwrapDEK: %v", err)
	}
	if !bytes.Equal(dek, out) {
		t.Fatalf("unwrap mismatch")
	}

	// wrong KEK must fail
	kek2 := DeriveKEK([]byte("pwd2"), salt)
	if _, err := UnwrapDEK(kek2, w); err == nil {
		t.Fatalf("unwrap with wrong kek must error")
	}
}

func TestEncryptDecryptBlob_Roundtrip_And_AAD(t *testing.T) {
	dek, _ := Rand(DEKLen)
	itemID := []byte("item-uuid-1")
	key, err := DeriveItemKey(dek, itemID)
	if err != nil {
		t.Fatalf("DeriveItemKey: %v", err)
	}
	userID := []byte("user-uuid-1")
	ver := int64(1)
	plain := []byte(`{"type":"text","meta":{"title":"t"},"data":"abc"}`)

	blob, err := EncryptBlob(key, userID, itemID, ver, plain)
	if err != nil {
		t.Fatalf("EncryptBlob: %v", err)
	}
	pt, err := DecryptBlob(key, userID, itemID, ver, blob)
	if err != nil {
		t.Fatalf("DecryptBlob: %v", err)
	}
	if !bytes.Equal(plain, pt) {
		t.Fatalf("decrypt mismatch")
	}

	// AAD tamper: wrong user
	if _, err := DecryptBlob(key, []byte("other-user"), itemID, ver, blob); err == nil {
		t.Fatalf("AAD user mismatch should error")
	}
	// AAD tamper: wrong item
	if _, err := DecryptBlob(key, userID, []byte("other-item"), ver, blob); err == nil {
		t.Fatalf("AAD item mismatch should error")
	}
	// AAD tamper: wrong ver
	if _, err := DecryptBlob(key, userID, itemID, ver+1, blob); err == nil {
		t.Fatalf("AAD ver mismatch should error")
	}
	// wrong key
	key2, _ := DeriveItemKey(dek, []byte("item-uuid-2"))
	if _, err := DecryptBlob(key2, userID, itemID, ver, blob); err == nil {
		t.Fatalf("wrong key should error")
	}
}
