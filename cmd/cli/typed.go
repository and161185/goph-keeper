// cmd/cli/typed.go
package main

import (
	"context"
	"encoding/base32"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"mime"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	pb "github.com/and161185/goph-keeper/gen/go/gophkeeper/v1"
	cc "github.com/and161185/goph-keeper/internal/crypto/clientcrypto"
	u "github.com/gofrs/uuid/v5"
)

// ------- generic builders -------

// buildTypedPayload packs {type, meta, data} as JSON bytes.
func buildTypedPayload(typ string, meta any, data any) ([]byte, error) {
	w := map[string]any{"type": typ, "meta": meta, "data": data}
	return json.Marshal(w)
}

// encryptForItem encrypts plaintext as blob_enc using HKDF(itemID) and AAD(userID||itemID||ver).
func encryptForItem(itemID, userID string, ver int64, plaintext []byte) ([]byte, error) {
	dek, err := loadDEK()
	if err != nil {
		return nil, errors.New("no DEK; login first")
	}
	key, err := cc.DeriveItemKey(dek, []byte(itemID))
	if err != nil {
		return nil, err
	}
	return cc.EncryptBlob(key, []byte(userID), []byte(itemID), ver, plaintext)
}

// upsertOne composes UpsertItems request for single item.
func upsertOne(addr, caPath string, insecure bool, token, itemID string, baseVer int64, blob []byte) (*pb.UpsertItemsResponse, error) {
	ctx, cancel := withTimeout()
	defer cancel()
	ccConn, cli, err := dial(ctx, addr, caPath, insecure, token)
	if err != nil {
		return nil, err
	}
	defer ccConn.Close()
	req := &pb.UpsertItemsRequest{
		Items: []*pb.UpsertItem{{Id: itemID, BaseVer: baseVer, BlobEnc: &pb.EncryptedBlob{Ciphertext: blob}}},
	}
	return cli.UpsertItems(ctx, req)
}

func pretty(b []byte) string {
	var out any
	if json.Unmarshal(b, &out) == nil {
		j, _ := json.MarshalIndent(out, "", "  ")
		return string(j)
	}
	return string(b)
}

// ------- validators -------

func autoUUID(id *string) {
	if *id == "" {
		v, _ := u.NewV4()
		*id = v.String()
	}
}

var reMMYY = regexp.MustCompile(`^\d{2}/\d{2}$`)

func validExp(mmyy string) bool { return reMMYY.MatchString(mmyy) }

func luhn(num string) bool {
	sum, alt := 0, false
	for i := len(num) - 1; i >= 0; i-- {
		c := int(num[i] - '0')
		if c < 0 || c > 9 {
			return false
		}
		if alt {
			c *= 2
			if c > 9 {
				c -= 9
			}
		}
		sum += c
		alt = !alt
	}
	return sum%10 == 0
}

func isBase32(s string) bool {
	_, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(s))
	return err == nil
}

// ------- commands -------

// cmdAddLogin creates or updates a login/password record from flags.
func cmdAddLogin(args []string, addr, caPath string, insecure bool) {
	fs := flag.NewFlagSet("add-login", flag.ExitOnError)
	id := fs.String("id", "", "item id (uuid, optional)")
	title := fs.String("title", "", "title")
	url := fs.String("url", "", "url")
	user := fs.String("username", "", "username")
	pass := fs.String("password", "", "password")
	note := fs.String("note", "", "note")
	base := fs.Int64("base", 0, "base version (0 for create)")
	_ = fs.Parse(args)

	autoUUID(id)
	if *user == "" || *pass == "" {
		fmt.Fprintln(os.Stderr, "username and password required")
		os.Exit(2)
	}
	meta := map[string]any{"title": *title, "url": *url, "username": *user, "note": *note}
	data := map[string]any{"password": *pass}
	pt, _ := buildTypedPayload("login", meta, data)

	token, err := loadToken()
	if err != nil {
		fail(err)
	}
	uid, err := loadUserID()
	if err != nil {
		fail(err)
	}
	blob, err := encryptForItem(*id, uid, *base+1, pt)
	if err != nil {
		fail(err)
	}
	resp, err := upsertOne(addr, caPath, insecure, token, *id, *base, blob)
	if err != nil {
		fail(err)
	}
	printJSON(resp.GetResults())
}

// cmdAddText creates or updates a text record from flags.
func cmdAddText(args []string, addr, caPath string, insecure bool) {
	fs := flag.NewFlagSet("add-text", flag.ExitOnError)
	id := fs.String("id", "", "item id (uuid, optional)")
	title := fs.String("title", "", "title")
	text := fs.String("text", "", "text")
	note := fs.String("note", "", "note")
	base := fs.Int64("base", 0, "base version (0 for create)")
	_ = fs.Parse(args)

	autoUUID(id)
	if *text == "" {
		fmt.Fprintln(os.Stderr, "text required")
		os.Exit(2)
	}
	meta := map[string]any{"title": *title, "note": *note}
	data := map[string]any{"text": *text}
	pt, _ := buildTypedPayload("text", meta, data)

	token, err := loadToken()
	if err != nil {
		fail(err)
	}
	uid, err := loadUserID()
	if err != nil {
		fail(err)
	}
	blob, err := encryptForItem(*id, uid, *base+1, pt)
	if err != nil {
		fail(err)
	}
	resp, err := upsertOne(addr, caPath, insecure, token, *id, *base, blob)
	if err != nil {
		fail(err)
	}
	printJSON(resp.GetResults())
}

// cmdAddCard creates or updates a card record with basic validation.
func cmdAddCard(args []string, addr, caPath string, insecure bool) {
	fs := flag.NewFlagSet("add-card", flag.ExitOnError)
	id := fs.String("id", "", "item id (uuid, optional)")
	title := fs.String("title", "", "title")
	name := fs.String("name", "", "cardholder")
	number := fs.String("number", "", "card number (digits)")
	exp := fs.String("exp", "", "MM/YY")
	cvc := fs.String("cvc", "", "CVC")
	note := fs.String("note", "", "note")
	base := fs.Int64("base", 0, "base version (0 for create)")
	_ = fs.Parse(args)

	autoUUID(id)
	if *name == "" || *number == "" || *exp == "" || *cvc == "" {
		fmt.Fprintln(os.Stderr, "name, number, exp, cvc required")
		os.Exit(2)
	}
	if !luhn(*number) || !validExp(*exp) || len(*cvc) < 3 || len(*cvc) > 4 {
		fmt.Fprintln(os.Stderr, "invalid card fields")
		os.Exit(2)
	}
	meta := map[string]any{"title": *title, "name": *name, "number": *number, "exp": *exp, "cvc": *cvc, "note": *note}
	data := map[string]any{}
	pt, _ := buildTypedPayload("card", meta, data)

	token, err := loadToken()
	if err != nil {
		fail(err)
	}
	uid, err := loadUserID()
	if err != nil {
		fail(err)
	}
	blob, err := encryptForItem(*id, uid, *base+1, pt)
	if err != nil {
		fail(err)
	}
	resp, err := upsertOne(addr, caPath, insecure, token, *id, *base, blob)
	if err != nil {
		fail(err)
	}
	printJSON(resp.GetResults())
}

// cmdAddBinary creates or updates a binary record from a file.
func cmdAddBinary(args []string, addr, caPath string, insecure bool) {
	fs := flag.NewFlagSet("add-binary", flag.ExitOnError)
	id := fs.String("id", "", "item id (uuid, optional)")
	title := fs.String("title", "", "title")
	file := fs.String("file", "", "path to file")
	note := fs.String("note", "", "note")
	base := fs.Int64("base", 0, "base version (0 for create)")
	_ = fs.Parse(args)

	autoUUID(id)
	if *file == "" {
		fmt.Fprintln(os.Stderr, "file required")
		os.Exit(2)
	}
	b, err := os.ReadFile(*file)
	if err != nil {
		fail(err)
	}
	fn := filepath.Base(*file)
	mt := mime.TypeByExtension(strings.ToLower(filepath.Ext(fn)))
	meta := map[string]any{"title": *title, "filename": fn, "mime": mt, "note": *note}
	pt, _ := buildTypedPayload("binary", meta, b)

	token, err := loadToken()
	if err != nil {
		fail(err)
	}
	uid, err := loadUserID()
	if err != nil {
		fail(err)
	}
	blob, err := encryptForItem(*id, uid, *base+1, pt)
	if err != nil {
		fail(err)
	}
	resp, err := upsertOne(addr, caPath, insecure, token, *id, *base, blob)
	if err != nil {
		fail(err)
	}
	printJSON(resp.GetResults())
}

// cmdAddOTP creates or updates an OTP secret record.
func cmdAddOTP(args []string, addr, caPath string, insecure bool) {
	fs := flag.NewFlagSet("add-otp", flag.ExitOnError)
	id := fs.String("id", "", "item id (uuid, optional)")
	title := fs.String("title", "", "title")
	secret := fs.String("secret", "", "base32 TOTP secret")
	issuer := fs.String("issuer", "", "issuer")
	digits := fs.Int("digits", 6, "digits (6 or 8)")
	period := fs.Int("period", 30, "period (seconds)")
	algo := fs.String("algo", "SHA1", "algo (SHA1/SHA256/SHA512)")
	note := fs.String("note", "", "note")
	base := fs.Int64("base", 0, "base version (0 for create)")
	_ = fs.Parse(args)

	autoUUID(id)
	if *secret == "" || !isBase32(*secret) || (*digits != 6 && *digits != 8) || *period <= 0 {
		fmt.Fprintln(os.Stderr, "invalid otp params")
		os.Exit(2)
	}
	meta := map[string]any{"title": *title, "issuer": *issuer, "digits": *digits, "period": *period, "algo": strings.ToUpper(*algo), "note": *note}
	data := map[string]any{"secret": strings.ToUpper(*secret)}
	pt, _ := buildTypedPayload("otp", meta, data)

	token, err := loadToken()
	if err != nil {
		fail(err)
	}
	uid, err := loadUserID()
	if err != nil {
		fail(err)
	}
	blob, err := encryptForItem(*id, uid, *base+1, pt)
	if err != nil {
		fail(err)
	}
	resp, err := upsertOne(addr, caPath, insecure, token, *id, *base, blob)
	if err != nil {
		fail(err)
	}
	printJSON(resp.GetResults())
}

// cmdShow decrypts and displays a record; for binary, can write to a file.
func cmdShow(args []string, addr, caPath string, insecure bool) {
	fs := flag.NewFlagSet("show", flag.ExitOnError)
	id := fs.String("id", "", "item id (uuid)")
	out := fs.String("out", "", "write binary data to file ('-'=stdout)")
	_ = fs.Parse(args)
	if *id == "" {
		fmt.Fprintln(os.Stderr, "need -id")
		os.Exit(2)
	}

	token, err := loadToken()
	if err != nil {
		fail(err)
	}
	ctx, cancel := withTimeout()
	defer cancel()
	ccConn, cli, err := dial(ctx, addr, caPath, insecure, token)
	if err != nil {
		fail(err)
	}
	defer ccConn.Close()

	it, err := cli.GetItem(ctx, &pb.GetItemRequest{Id: *id})
	if err != nil {
		fail(err)
	}
	if it.GetDeleted() {
		fmt.Fprintln(os.Stderr, "item is deleted")
		os.Exit(1)
	}

	// decrypt
	dek, err := loadDEK()
	if err != nil {
		fail(errors.New("no DEK; login first"))
	}
	uid, err := loadUserID()
	if err != nil {
		fail(err)
	}
	key, err := cc.DeriveItemKey(dek, []byte(*id))
	if err != nil {
		fail(err)
	}
	pt, err := cc.DecryptBlob(key, []byte(uid), []byte(*id), it.GetVer(), it.GetBlobEnc().GetCiphertext())
	if err != nil {
		fail(fmt.Errorf("decrypt: %w", err))
	}

	// parse type
	var obj struct {
		Type string          `json:"type"`
		Meta json.RawMessage `json:"meta"`
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(pt, &obj); err != nil {
		fail(err)
	}

	switch obj.Type {
	case "binary":
		var m struct{ Filename, Mime string }
		_ = json.Unmarshal(obj.Meta, &m)
		var data []byte
		_ = json.Unmarshal(obj.Data, &data)
		var w io.Writer = os.Stdout
		if *out != "" && *out != "-" {
			f, err := os.Create(*out)
			if err != nil {
				fail(err)
			}
			defer f.Close()
			w = f
		}
		if _, err := w.Write(data); err != nil {
			fail(err)
		}
		if *out != "-" {
			fmt.Printf("wrote %dB to %s\n", len(data), choose(*out, m.Filename))
		}
	default:
		fmt.Println(pretty(obj.Meta))

		fmt.Printf("data=%sB (use type-specific export if needed)\n", strconv.Itoa(len(obj.Data)))
	}
}

func withTimeout() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 30*time.Second)
}
func choose(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
