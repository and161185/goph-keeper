// Package service contains application services for authentication and items.
package service

import (
	"context"
	"errors"
	"time"

	pkgcrypto "github.com/and161185/goph-keeper/internal/crypto"
	"github.com/and161185/goph-keeper/internal/errs"
	"github.com/and161185/goph-keeper/internal/limiter"
	"github.com/and161185/goph-keeper/internal/model"
	"github.com/and161185/goph-keeper/internal/repository"
	"github.com/gofrs/uuid/v5"
	"github.com/golang-jwt/jwt/v5"
)

// AuthService defines authentication and bootstrap operations.
type AuthService interface {
	// Register creates a new user with secure password hashing.
	Register(ctx context.Context, username, password string) (userID string, err error)
	// LoginWithIP applies rate-limiting and authenticates the user.
	LoginWithIP(ctx context.Context, username, password string, ip string) (tokens model.Tokens, user model.User, err error)
	// SetWrappedDEK stores client's wrapped DEK if none is set.
	SetWrappedDEK(ctx context.Context, userID uuid.UUID, wrapped []byte) error
}

type AuthServiceImpl struct {
	users     repository.UserRepository
	signKey   []byte
	accessTTL time.Duration
	lim       limiter.Limiter
}

// NewAuthService constructs AuthService with required dependencies.
func NewAuthService(users repository.UserRepository, signKey []byte, accessTTL time.Duration, lim limiter.Limiter) *AuthServiceImpl {
	return &AuthServiceImpl{users: users, signKey: signKey, accessTTL: accessTTL, lim: lim}
}

// Register creates a new user record with per-user salts.
func (s *AuthServiceImpl) Register(ctx context.Context, username, password string) (string, error) {
	if username == "" || password == "" {
		return "", errors.New("empty username/password")
	}
	uid, err := uuid.NewV4()
	if err != nil {
		return "", err
	}
	saltAuth, err := pkgcrypto.RandBytes(16)
	if err != nil {
		return "", err
	}
	kekSalt, err := pkgcrypto.RandBytes(16)
	if err != nil {
		return "", err
	}
	pwdHash := pkgcrypto.HashPassword([]byte(password), saltAuth)

	u := &model.User{
		ID:         uid,
		Username:   username,
		PwdHash:    pwdHash,
		SaltAuth:   saltAuth,
		KekSalt:    kekSalt,
		WrappedDEK: []byte{}, // empty for now (MVP)
	}
	if err := s.users.Create(ctx, u); err != nil {
		return "", err
	}
	return uid.String(), nil
}

// LoginWithIP authenticates with rate limiting by (username, ip).
func (s *AuthServiceImpl) LoginWithIP(ctx context.Context, username, password, ip string) (model.Tokens, model.User, error) {
	ipHash := limiter.HashIP(ip)

	// Check if requests are currently allowed for this (user, ip).
	allowed, _, err := s.lim.Allow(ctx, username, ipHash)
	if err != nil {
		return model.Tokens{}, model.User{}, err
	}
	if !allowed {
		return model.Tokens{}, model.User{}, errs.ErrRateLimited
	}

	u, err := s.users.GetByUsername(ctx, username)
	if err != nil || !pkgcrypto.VerifyPassword([]byte(password), u.SaltAuth, u.PwdHash) {
		// Record failure; if threshold reached — return rate-limited.
		if blocked, _, ferr := s.lim.Failure(ctx, username, ipHash); ferr == nil && blocked {
			return model.Tokens{}, model.User{}, errs.ErrRateLimited
		}
		if err == nil {
			// hide existence of the user on wrong password
			return model.Tokens{}, model.User{}, errs.ErrUnauthorized
		}
		// user lookup error masked as unauthorized
		return model.Tokens{}, model.User{}, errs.ErrUnauthorized
	}

	// Success: reset counters (best-effort).
	_ = s.lim.Success(ctx, username, ipHash)

	access, exp, err := s.issueAccessToken(u.ID)
	if err != nil {
		return model.Tokens{}, model.User{}, err
	}
	return model.Tokens{AccessToken: access, ExpiresAt: exp}, *u, nil
}

// issueAccessToken creates a signed HS256 JWT for the given subject.
func (s *AuthServiceImpl) issueAccessToken(userID uuid.UUID) (string, time.Time, error) {
	now := time.Now()
	exp := now.Add(s.accessTTL)
	claims := jwt.RegisteredClaims{
		Subject:   userID.String(),
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(exp),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString(s.signKey)
	return signed, exp, err
}

// SetWrappedDEK persists wrapped DEK if not yet initialized.
func (s *AuthServiceImpl) SetWrappedDEK(ctx context.Context, userID uuid.UUID, wrapped []byte) error {
	if userID == uuid.Nil || len(wrapped) == 0 {
		return errors.New("validation: userID/wrapped_dek")
	}
	return s.users.SetWrappedDEKIfEmpty(ctx, userID, wrapped)
}
