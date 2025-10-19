package service

import (
	"context"
	"errors"
	"testing"
	"time"

	pkgcrypto "github.com/and161185/goph-keeper/internal/crypto"
	"github.com/and161185/goph-keeper/internal/errs"
	"github.com/and161185/goph-keeper/internal/limiter"
	"github.com/and161185/goph-keeper/internal/model"
	"github.com/and161185/goph-keeper/internal/repository"
	"github.com/gofrs/uuid/v5"
)

type fakeUsers struct {
	byName map[string]*model.User

	createErr error
	getErr    error

	setWrappedErr error
}

var _ repository.UserRepository = (*fakeUsers)(nil)

func (f *fakeUsers) Create(_ context.Context, u *model.User) error {
	if f.createErr != nil {
		return f.createErr
	}
	if f.byName == nil {
		f.byName = map[string]*model.User{}
	}
	if _, exists := f.byName[u.Username]; exists {
		return errs.ErrAlreadyExists
	}
	cpy := *u
	f.byName[u.Username] = &cpy
	return nil
}
func (f *fakeUsers) GetByID(_ context.Context, id uuid.UUID) (*model.User, error) {
	for _, u := range f.byName {
		if u.ID == id {
			c := *u
			return &c, nil
		}
	}
	return nil, errs.ErrNotFound
}
func (f *fakeUsers) GetByUsername(_ context.Context, username string) (*model.User, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	u, ok := f.byName[username]
	if !ok {
		return nil, errs.ErrNotFound
	}
	c := *u
	return &c, nil
}
func (f *fakeUsers) SetWrappedDEKIfEmpty(_ context.Context, id uuid.UUID, wrapped []byte) error {
	if f.setWrappedErr != nil {
		return f.setWrappedErr
	}
	for _, u := range f.byName {
		if u.ID == id {
			if len(u.WrappedDEK) != 0 {
				return errs.ErrVersionConflict
			}
			u.WrappedDEK = append([]byte(nil), wrapped...)
			return nil
		}
	}
	return errs.ErrNotFound
}

type fakeLimiter struct {
	allowOK  bool
	allowErr error

	failBlocked bool
	failErr     error

	successErr error

	allowCalls   int
	failureCalls int
	successCalls int
}

var _ limiter.Limiter = (*fakeLimiter)(nil)

func (l *fakeLimiter) Allow(context.Context, string, []byte) (bool, time.Duration, error) {
	l.allowCalls++
	return l.allowOK, 0, l.allowErr
}
func (l *fakeLimiter) Success(context.Context, string, []byte) error {
	l.successCalls++
	return l.successErr
}
func (l *fakeLimiter) Failure(context.Context, string, []byte) (bool, time.Duration, error) {
	l.failureCalls++
	return l.failBlocked, 0, l.failErr
}

func TestAuth_Register_Basics(t *testing.T) {
	t.Parallel()
	users := &fakeUsers{byName: map[string]*model.User{}}
	s := NewAuthService(users, []byte("k"), time.Minute, &fakeLimiter{})

	if _, err := s.Register(context.Background(), "", ""); err == nil {
		t.Fatalf("want validation error on empty username/password")
	}

	id, err := s.Register(context.Background(), "alice", "pwd")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if id == "" {
		t.Fatalf("empty user id")
	}

	if _, err := s.Register(context.Background(), "alice", "pwd2"); err == nil {
		t.Fatalf("want repo error on duplicate username")
	}

	users.createErr = errors.New("boom")
	if _, err := s.Register(context.Background(), "bob", "pwd"); err == nil {
		t.Fatalf("want propagated repo error")
	}
}

func TestAuth_LoginWithIP_RateLimiterAndCreds(t *testing.T) {
	t.Parallel()

	saltAuth, _ := pkgcrypto.RandBytes(16)
	kekSalt, _ := pkgcrypto.RandBytes(16)
	pw := []byte("correct")
	u := &model.User{
		ID:       uuid.Must(uuid.NewV4()),
		Username: "alice",
		SaltAuth: saltAuth,
		KekSalt:  kekSalt,
		PwdHash:  pkgcrypto.HashPassword(pw, saltAuth),
	}

	users := &fakeUsers{byName: map[string]*model.User{"alice": u}}
	lim := &fakeLimiter{allowOK: true}
	s := NewAuthService(users, []byte("secret"), 2*time.Minute, lim)

	lim.allowErr = errors.New("lim-err")
	if _, _, err := s.LoginWithIP(context.Background(), "alice", "correct", "1.2.3.4"); err == nil {
		t.Fatalf("want limiter error propagate")
	}
	lim.allowErr = nil

	lim.allowOK = false
	if _, _, err := s.LoginWithIP(context.Background(), "alice", "correct", "1.2.3.4"); !errors.Is(err, errs.ErrRateLimited) {
		t.Fatalf("want ErrRateLimited, got %v", err)
	}
	lim.allowOK = true

	users.getErr = errs.ErrNotFound
	if _, _, err := s.LoginWithIP(context.Background(), "nope", "x", ""); !errors.Is(err, errs.ErrUnauthorized) {
		t.Fatalf("want ErrUnauthorized on missing user, got %v", err)
	}
	users.getErr = nil

	lim.failBlocked = true
	if _, _, err := s.LoginWithIP(context.Background(), "alice", "wrong", ""); !errors.Is(err, errs.ErrRateLimited) {
		t.Fatalf("want ErrRateLimited on blocked after failure, got %v", err)
	}

	lim.failBlocked = false
	if _, _, err := s.LoginWithIP(context.Background(), "alice", "wrong", ""); !errors.Is(err, errs.ErrUnauthorized) {
		t.Fatalf("want ErrUnauthorized on wrong password, got %v", err)
	}

	tok, gotUser, err := s.LoginWithIP(context.Background(), "alice", "correct", "127.0.0.1:123")
	if err != nil {
		t.Fatalf("LoginWithIP success: %v", err)
	}
	if tok.AccessToken == "" || tok.ExpiresAt.Before(time.Now()) {
		t.Fatalf("bad token: %+v", tok)
	}
	if gotUser.ID != u.ID || len(gotUser.KekSalt) == 0 {
		t.Fatalf("bad user returned: %+v", gotUser)
	}
	if lim.successCalls == 0 {
		t.Fatalf("expected Success() to be called")
	}
}

func TestAuth_issueAccessToken_UsedViaLoginTTL(t *testing.T) {
	t.Parallel()

	users := &fakeUsers{byName: map[string]*model.User{}}
	lim := &fakeLimiter{allowOK: true}
	s := NewAuthService(users, []byte("k"), 1*time.Second, lim)

	salt, _ := pkgcrypto.RandBytes(16)
	u := &model.User{
		ID:       uuid.Must(uuid.NewV4()),
		Username: "bob",
		SaltAuth: salt,
		KekSalt:  []byte("x"),
		PwdHash:  pkgcrypto.HashPassword([]byte("p"), salt),
	}
	_ = users.Create(context.Background(), u)

	tk, _, err := s.LoginWithIP(context.Background(), "bob", "p", "")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if tk.AccessToken == "" {
		t.Fatalf("empty token")
	}

	if time.Until(tk.ExpiresAt) <= 0 {
		t.Fatalf("token already expired: %v", tk.ExpiresAt)
	}
}

func TestAuth_SetWrappedDEK(t *testing.T) {
	t.Parallel()

	users := &fakeUsers{byName: map[string]*model.User{}}
	s := NewAuthService(users, []byte("k"), time.Minute, &fakeLimiter{allowOK: true})

	uid := uuid.Must(uuid.NewV4())
	users.byName["u"] = &model.User{ID: uid, Username: "u", WrappedDEK: []byte{}}

	if err := s.SetWrappedDEK(context.Background(), uuid.Nil, []byte{1}); err == nil {
		t.Fatalf("want validation error (nil userID)")
	}
	if err := s.SetWrappedDEK(context.Background(), uid, nil); err == nil {
		t.Fatalf("want validation error (empty wrapped)")
	}

	if err := s.SetWrappedDEK(context.Background(), uid, []byte{7, 7}); err != nil {
		t.Fatalf("SetWrappedDEK: %v", err)
	}

	if err := s.SetWrappedDEK(context.Background(), uid, []byte{8}); !errors.Is(err, errs.ErrVersionConflict) {
		t.Fatalf("want ErrVersionConflict on second set, got %v", err)
	}

	users.setWrappedErr = errors.New("boom")
	if err := s.SetWrappedDEK(context.Background(), uid, []byte{9}); err == nil {
		t.Fatalf("want propagated repo error")
	}
}
