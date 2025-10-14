package main

import (
	"encoding/json"
	"testing"
	"time"

	u "github.com/gofrs/uuid/v5"
)

func Test_buildTypedPayload_Roundtrip(t *testing.T) {
	t.Parallel()

	pt, err := buildTypedPayload("login",
		map[string]any{"title": "gmail"}, map[string]any{"password": "x"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got struct {
		Type string         `json:"type"`
		Meta map[string]any `json:"meta"`
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(pt, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Type != "login" || got.Meta["title"] != "gmail" || got.Data["password"] != "x" {
		t.Fatalf("mismatch: %+v", got)
	}
}

func Test_pretty_JSON_and_Raw(t *testing.T) {
	t.Parallel()

	j := []byte(`{"a":1,"b":[2,3]}`)
	p := pretty(j)
	var back map[string]any
	if err := json.Unmarshal([]byte(p), &back); err != nil {
		t.Fatalf("pretty must keep valid json: %v", err)
	}
	raw := []byte("not-json")
	if pretty(raw) != "not-json" {
		t.Fatalf("pretty(raw) should return the same string")
	}
}

func Test_autoUUID(t *testing.T) {
	t.Parallel()

	var id string
	autoUUID(&id)
	if id == "" {
		t.Fatalf("should set uuid when empty")
	}
	if _, err := u.FromString(id); err != nil {
		t.Fatalf("not a uuid: %v", err)
	}

	keep := "00000000-0000-0000-0000-000000000000"
	autoUUID(&keep)
	if keep != "00000000-0000-0000-0000-000000000000" {
		t.Fatalf("must not change non-empty id")
	}
}

func Test_validExp(t *testing.T) {
	t.Parallel()
	for _, s := range []string{"01/25", "12/99", "00/00", "13/20"} { // regex-проверка, не валидирует месяц
		if !validExp(s) {
			t.Fatalf("expected valid by regex: %s", s)
		}
	}
	for _, s := range []string{"1/25", "1/2", "aa/bb", "012/34"} {
		if validExp(s) {
			t.Fatalf("expected invalid: %s", s)
		}
	}
}

func Test_luhn(t *testing.T) {
	t.Parallel()

	for _, n := range []string{
		"4532015112830366",
		"79927398713",
	} {
		if !luhn(n) {
			t.Fatalf("luhn valid failed: %s", n)
		}
	}

	for _, n := range []string{"4532015112830367", "79927398710", "12a34"} {
		if luhn(n) {
			t.Fatalf("luhn should fail: %s", n)
		}
	}
}

func Test_isBase32(t *testing.T) {
	t.Parallel()
	if !isBase32("JBSWY3DPEHPK3PXP") {
		t.Fatalf("expected valid base32")
	}
	if !isBase32("jbswy3dpehpk3pxp") {
		t.Fatalf("expected valid base32 (lowercase)")
	}
	for _, s := range []string{"abc!", "====", "12345"} {
		if isBase32(s) {
			t.Fatalf("expected invalid: %q", s)
		}
	}
}

func Test_choose(t *testing.T) {
	t.Parallel()
	if choose("a", "b") != "a" {
		t.Fatalf("choose a")
	}
	if choose("", "b") != "b" {
		t.Fatalf("choose b")
	}
}

func Test_withTimeout(t *testing.T) {
	t.Parallel()
	start := time.Now()
	ctx, cancel := withTimeout()
	defer cancel()
	dl, ok := ctx.Deadline()
	if !ok {
		t.Fatalf("deadline not set")
	}
	rem := time.Until(dl)
	if rem < 25*time.Second || rem > 35*time.Second {
		t.Fatalf("unexpected timeout window: %v (since start: %v)", rem, dl.Sub(start))
	}
}
