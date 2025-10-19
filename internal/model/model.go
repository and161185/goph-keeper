// Package model defines domain entities used by services and repositories.
package model

import (
	"time"

	"github.com/gofrs/uuid/v5"
)

// Tokens collects issued access/refresh tokens (refresh optional).
type Tokens struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time // access token expiry (for diagnostics)
}

// EncryptedBlob is an opaque ciphertext produced on the client side.
type EncryptedBlob []byte

// Item is a single stored record, including encrypted payload and versioning metadata.
type Item struct {
	ID        uuid.UUID     // client-generated PK
	UserID    uuid.UUID     // FK -> users.id
	BlobEnc   EncryptedBlob // opaque AEAD blob
	Ver       int64         // monotonically increasing version (>= 0)
	Deleted   bool          // tombstone flag
	UpdatedAt time.Time     // maintained by DB triggers or repo
}

// UpsertItem is a client change intent with optimistic concurrency base version.
type UpsertItem struct {
	ID      uuid.UUID
	BaseVer int64
	BlobEnc EncryptedBlob
}

// ItemVersion reports the new version after a successful change.
type ItemVersion struct {
	ID        uuid.UUID
	NewVer    int64
	UpdatedAt time.Time
}

// Change describes a single item mutation for delta sync.
type Change struct {
	ID        uuid.UUID
	Ver       int64
	Deleted   bool
	UpdatedAt time.Time
	BlobEnc   EncryptedBlob // nil if Deleted==true (server MAY omit)
}

// User represents an account stored on the server. Sensitive keys are never stored in plaintext.
type User struct {
	ID         uuid.UUID // PK
	Username   string    // unique
	PwdHash    []byte    // Argon2id(password, SaltAuth)
	SaltAuth   []byte    // per-user auth salt
	KekSalt    []byte    // per-user KEK salt (for client-side KEK derivation)
	WrappedDEK []byte    // client-produced AEAD(DEK) wrapped by KEK
	CreatedAt  time.Time
}
