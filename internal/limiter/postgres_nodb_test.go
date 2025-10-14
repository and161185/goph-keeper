package limiter

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

/************ fake pgx ************/
type fakeRow struct{ scan func(dest ...any) error }

func (r fakeRow) Scan(dest ...any) error { return r.scan(dest...) }

type fakePool struct {
	qrErr         error
	qrBlockedTill *time.Time
	qrUpdatedAt   time.Time
	qrFailsRet    int

	lastExecSQL string
	execErr     error
}

func (f *fakePool) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	f.lastExecSQL = sql
	return pgconn.CommandTag{}, f.execErr
}

func (f *fakePool) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	switch {

	case contains(sql, "SELECT blocked_until"):
		return fakeRow{scan: func(dest ...any) error {
			if f.qrErr != nil {
				return f.qrErr
			}

			if f.qrBlockedTill != nil {
				*(dest[0].(*time.Time)) = *f.qrBlockedTill
			} else {
				*(dest[0].(*time.Time)) = time.Time{} // 'epoch'
			}
			*(dest[1].(*time.Time)) = f.qrUpdatedAt
			return nil
		}}

	case contains(sql, "RETURNING fail_count"):
		return fakeRow{scan: func(dest ...any) error {
			if f.qrErr != nil {
				return f.qrErr
			}
			*(dest[0].(*int)) = f.qrFailsRet
			return nil
		}}
	default:
		return fakeRow{scan: func(dest ...any) error { return errors.New("unexpected query") }}
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool { return (stringIndex(s, sub) >= 0) })()
}
func stringIndex(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestAllow_NoRow_Allows(t *testing.T) {
	fp := &fakePool{qrErr: pgx.ErrNoRows}
	l := NewPGWithQuerier(fp, 15*time.Minute, 5, 15*time.Minute)

	ok, dur, err := l.Allow(context.Background(), "u", []byte("h"))
	if err != nil || !ok || dur != 0 {
		t.Fatalf("Allow no-row: ok=%v dur=%v err=%v", ok, dur, err)
	}
}

func TestAllow_BlockedUntilFuture(t *testing.T) {
	fut := time.Now().Add(10 * time.Minute)
	fp := &fakePool{qrBlockedTill: &fut, qrUpdatedAt: time.Now()}
	l := NewPGWithQuerier(fp, 15*time.Minute, 5, 15*time.Minute)

	ok, dur, err := l.Allow(context.Background(), "u", []byte("h"))
	if err != nil || ok || dur <= 0 {
		t.Fatalf("Allow blocked: ok=%v dur=%v err=%v", ok, dur, err)
	}
}

func TestAllow_PastOrEpoch_Allows(t *testing.T) {
	past := time.Now().Add(-time.Minute)
	fp := &fakePool{qrBlockedTill: &past, qrUpdatedAt: time.Now()}
	l := NewPGWithQuerier(fp, 15*time.Minute, 5, 15*time.Minute)

	ok, dur, err := l.Allow(context.Background(), "u", []byte("h"))
	if err != nil || !ok || dur != 0 {
		t.Fatalf("Allow past: ok=%v dur=%v err=%v", ok, dur, err)
	}
}

func TestAllow_DBError_Propagates(t *testing.T) {
	fp := &fakePool{qrErr: errors.New("db boom")}
	l := NewPGWithQuerier(fp, 15*time.Minute, 5, 15*time.Minute)

	ok, _, err := l.Allow(context.Background(), "u", []byte("h"))
	if err == nil || ok {
		t.Fatalf("want error propagate, got ok=%v err=%v", ok, err)
	}
}

func TestSuccess_ExecError_Propagates(t *testing.T) {
	fp := &fakePool{execErr: errors.New("exec fail")}
	l := NewPGWithQuerier(fp, 15*time.Minute, 5, 15*time.Minute)

	if err := l.Success(context.Background(), "u", []byte("h")); err == nil {
		t.Fatalf("want exec error")
	}
}

func TestSuccess_OK(t *testing.T) {
	fp := &fakePool{}
	l := NewPGWithQuerier(fp, 15*time.Minute, 5, 15*time.Minute)

	if err := l.Success(context.Background(), "u", []byte("h")); err != nil {
		t.Fatalf("success err: %v", err)
	}
	if !contains(fp.lastExecSQL, "INSERT INTO auth_limiter") {
		t.Fatalf("unexpected exec: %s", fp.lastExecSQL)
	}
}

func TestFailure_Increments_NoBlock(t *testing.T) {
	fp := &fakePool{qrFailsRet: 2}
	l := NewPGWithQuerier(fp, 5*time.Minute, 5, 15*time.Minute)

	blocked, dur, err := l.Failure(context.Background(), "u", []byte("h"))
	if err != nil || blocked || dur != 0 {
		t.Fatalf("Failure no block: blocked=%v dur=%v err=%v", blocked, dur, err)
	}
}

func TestFailure_BlocksAtThreshold(t *testing.T) {
	fp := &fakePool{qrFailsRet: 5}
	l := NewPGWithQuerier(fp, 5*time.Minute, 5, 10*time.Minute)

	blocked, dur, err := l.Failure(context.Background(), "u", []byte("h"))
	if err != nil || !blocked || dur != 10*time.Minute {
		t.Fatalf("Failure block: blocked=%v dur=%v err=%v", blocked, dur, err)
	}
	if !contains(fp.lastExecSQL, "UPDATE auth_limiter SET blocked_until") {
		t.Fatalf("must update blocked_until, exec=%s", fp.lastExecSQL)
	}
}

func TestFailure_DBErrorOnReturning(t *testing.T) {
	fp := &fakePool{qrErr: errors.New("query error")}
	l := NewPGWithQuerier(fp, 5*time.Minute, 5, 10*time.Minute)

	if _, _, err := l.Failure(context.Background(), "u", []byte("h")); err == nil {
		t.Fatalf("want error from returning fail_count")
	}
}

func TestHashIP_Determinism(t *testing.T) {
	a := HashIP("1.2.3.4:123")
	b := HashIP("1.2.3.4:123")
	c := HashIP("5.6.7.8:321")
	if string(a) != string(b) || string(a) == string(c) || len(a) != 32 {
		t.Fatalf("hash mismatch/len: %d", len(a))
	}
}
