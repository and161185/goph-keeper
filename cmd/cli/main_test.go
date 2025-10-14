package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func withTmpConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	return filepath.Join(dir, "gophkeeper")
}

func Test_cfgDir_And_Paths(t *testing.T) {
	_ = withTmpConfig(t)
	got := cfgDir()
	base := os.Getenv("XDG_CONFIG_HOME") + "/gophkeeper"
	if got != base {
		t.Fatalf("cfgDir=%q, want %q", got, base)
	}
	if !strings.HasPrefix(tokenPath(), base) || !strings.HasSuffix(tokenPath(), "token.json") {
		t.Fatalf("tokenPath unexpected: %s", tokenPath())
	}
	if !strings.HasPrefix(dekPath(), base) || !strings.HasSuffix(dekPath(), "dek.bin") {
		t.Fatalf("dekPath unexpected: %s", dekPath())
	}
}

func Test_token_SaveLoad(t *testing.T) {
	_ = withTmpConfig(t)

	if _, err := loadToken(); err == nil {
		t.Fatalf("expected error when token file missing")
	}
	now := time.Now().Add(1 * time.Minute)
	if err := saveToken("tok", now); err != nil {
		t.Fatalf("saveToken: %v", err)
	}
	tok, err := loadToken()
	if err != nil || tok != "tok" {
		t.Fatalf("loadToken: tok=%q err=%v", tok, err)
	}
	if err := saveToken("tok2", time.Now().Add(-time.Minute)); err != nil {
		t.Fatalf("saveToken expired: %v", err)
	}
	if _, err := loadToken(); err == nil {
		t.Fatalf("want error for expired token")
	}
}

func Test_saveLoadDEK(t *testing.T) {
	_ = withTmpConfig(t)

	if _, err := loadDEK(); err == nil {
		t.Fatalf("expected error when dek missing")
	}
	dek := []byte{1, 2, 3}
	if err := saveDEK(dek); err != nil {
		t.Fatalf("saveDEK: %v", err)
	}
	got, err := loadDEK()
	if err != nil || string(got) != string(dek) {
		t.Fatalf("loadDEK mismatch: %v %v", got, err)
	}
}

func Test_saveLoadUserID(t *testing.T) {
	base := withTmpConfig(t)
	_ = os.MkdirAll(cfgDir(), 0o700)

	if _, err := loadUserID(); err == nil {
		t.Fatalf("expected error when user_id missing")
	}
	if err := saveUserID("abc-123\n"); err != nil {
		t.Fatalf("saveUserID: %v", err)
	}
	got, err := loadUserID()
	if err != nil || got != "abc-123" {
		t.Fatalf("loadUserID: %q %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(base, "user_id")); err != nil {
		t.Fatalf("user_id file missing: %v", err)
	}
}

func Test_readAll_File_And_Stdin(t *testing.T) {
	t.Parallel()

	// file path
	tmp := filepath.Join(t.TempDir(), "f.txt")
	_ = os.WriteFile(tmp, []byte("hello"), 0o600)
	b, err := readAll(tmp)
	if err != nil || string(b) != "hello" {
		t.Fatalf("readAll(file): %q %v", b, err)
	}

	// stdin
	r, w, _ := os.Pipe()
	old := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = old }()
	go func() { _, _ = io.WriteString(w, "from-stdin"); _ = w.Close() }()
	b, err = readAll("-")
	if err != nil || string(b) != "from-stdin" {
		t.Fatalf("readAll(stdin): %q %v", b, err)
	}
}

func Test_printJSON_WritesPretty(t *testing.T) {
	t.Parallel()

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	defer func() { os.Stdout = old }()

	printJSON(map[string]any{"a": 1})
	_ = w.Close()
	out, _ := io.ReadAll(r)

	var m map[string]any
	if json.Unmarshal(out, &m) != nil || m["a"] != float64(1) {
		t.Fatalf("printJSON produced invalid json: %s", string(out))
	}
	if !bytes.Contains(out, []byte("\n")) {
		t.Fatalf("printJSON should indent")
	}
}

func Test_tsString(t *testing.T) {
	t.Parallel()

	if tsString(nil) != "" {
		t.Fatalf("nil timestamp should be empty string")
	}
	now := time.Now().UTC().Truncate(time.Second)
	ts := timestamppb.New(now)
	s := tsString(ts)
	if !strings.Contains(s, now.Format("2006-01-02")) {
		t.Fatalf("tsString output unexpected: %s", s)
	}
}

func Test_bearerCreds_Metadata(t *testing.T) {
	t.Parallel()

	b := bearerCreds{token: "T"}
	md, err := b.GetRequestMetadata(context.Background())
	if err != nil {
		t.Fatalf("GetRequestMetadata: %v", err)
	}
	if md["authorization"] != "Bearer T" {
		t.Fatalf("auth header mismatch: %v", md)
	}
	if !b.RequireTransportSecurity() {
		t.Fatalf("bearerCreds must require TLS")
	}
}

func Test_loadTLS_Variants(t *testing.T) {
	t.Parallel()

	// insecure
	creds, err := loadTLS("", true)
	if err != nil || creds == nil {
		t.Fatalf("insecure: %v %v", creds, err)
	}

	// system default (no caPath)
	creds, err = loadTLS("", false)
	if err != nil || creds == nil {
		t.Fatalf("default tls: %v %v", creds, err)
	}

	// bad CA file
	tmp := filepath.Join(t.TempDir(), "bad.pem")
	_ = os.WriteFile(tmp, []byte("not pem"), 0o600)
	creds, err = loadTLS(tmp, false)
	if err == nil || creds != nil {
		t.Fatalf("bad CA should error, got creds=%v err=%v", creds, err)
	}

	// sanity check type
	_ = credentials.TransportCredentials(nil) // compile-time reference
}
