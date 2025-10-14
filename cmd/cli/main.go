// Command gk is a CLI client for the GophKeeper service.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	pb "github.com/and161185/goph-keeper/gen/go/gophkeeper/v1"
	clientcrypto "github.com/and161185/goph-keeper/internal/crypto/clientcrypto"
	u "github.com/gofrs/uuid/v5"
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ---- config/token store ----

type tokenFile struct {
	AccessToken string    `json:"access_token"`
	ExpiresAt   time.Time `json:"expires_at"`
}

func cfgDir() string {
	if v := os.Getenv("XDG_CONFIG_HOME"); v != "" {
		return filepath.Join(v, "gophkeeper")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "gophkeeper")
}

func tokenPath() string { return filepath.Join(cfgDir(), "token.json") }

func saveToken(tok string, exp time.Time) error {
	_ = os.MkdirAll(cfgDir(), 0o700)
	f, err := os.Create(tokenPath())
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(tokenFile{AccessToken: tok, ExpiresAt: exp})
}

func loadToken() (string, error) {
	b, err := os.ReadFile(tokenPath())
	if err != nil {
		return "", err
	}
	var tf tokenFile
	if err := json.Unmarshal(b, &tf); err != nil {
		return "", err
	}
	if tf.AccessToken == "" || time.Now().After(tf.ExpiresAt) {
		return "", errors.New("no valid token (login required)")
	}
	return tf.AccessToken, nil
}

func dekPath() string { return filepath.Join(cfgDir(), "dek.bin") }

func saveDEK(dek []byte) error {
	_ = os.MkdirAll(cfgDir(), 0o700)
	return os.WriteFile(dekPath(), dek, 0o600)
}
func loadDEK() ([]byte, error) {
	return os.ReadFile(dekPath())
}

// ---- grpc dial ----

type bearerCreds struct{ token string }

func (b bearerCreds) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{"authorization": "Bearer " + b.token}, nil
}
func (b bearerCreds) RequireTransportSecurity() bool { return true }

func loadTLS(caPath string, insecure bool) (credentials.TransportCredentials, error) {
	if insecure {
		return credentials.NewTLS(&tls.Config{InsecureSkipVerify: true}), nil
	}
	if caPath == "" {
		return credentials.NewClientTLSFromCert(nil, ""), nil
	}
	pem, err := os.ReadFile(caPath)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("bad CA cert")
	}
	return credentials.NewTLS(&tls.Config{RootCAs: pool}), nil
}

func dial(ctx context.Context, addr, caPath string, insecure bool, bearer string) (*grpc.ClientConn, pb.GophKeeperClient, error) {
	creds, err := loadTLS(caPath, insecure)
	if err != nil {
		return nil, nil, err
	}
	opts := []grpc.DialOption{grpc.WithTransportCredentials(creds)}
	if bearer != "" {
		opts = append(opts, grpc.WithPerRPCCredentials(bearerCreds{token: bearer}))
	}
	//nolint:staticcheck // DialContext is supported through 1.x; migrate when grpc.NewClient is stable
	cc, err := grpc.DialContext(ctx, addr, opts...)
	if err != nil {
		return nil, nil, err
	}
	return cc, pb.NewGophKeeperClient(cc), nil
}

// ---- utils ----

func readAll(p string) ([]byte, error) {
	if p == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(p)
}

func printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func saveUserID(uid string) error {
	return os.WriteFile(filepath.Join(cfgDir(), "user_id"), []byte(strings.TrimSpace(uid)), 0o600)
}
func loadUserID() (string, error) {
	b, err := os.ReadFile(filepath.Join(cfgDir(), "user_id"))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func usage() {
	fmt.Fprintf(os.Stderr, `gk CLI
Usage:
  gk -addr HOST:PORT [-cacert file | -insecure] <cmd> [args]

Commands:
  version
  register   -u <username> -p <password>
  login      -u <username> -p <password>           (saves token)
  list                                         (GetChanges since 0)
  sync       -since <ver>
  get        -id <uuid>
  add        -id <uuid> -file <blob>               (base_ver=0)
  edit       -id <uuid> -base <ver> -file <blob>
  rm         -id <uuid> -base <ver>
`)
	os.Exit(2)
}

// ---- main ----

var (
	version   = "dev"
	buildDate = "unknown"
)

// main dispatches subcommands and configures TLS/auth for RPC calls.
func main() {
	// global flags
	addr := flag.String("addr", "localhost:8443", "server addr")
	caPath := flag.String("cacert", "", "CA cert (PEM)")
	insecure := flag.Bool("insecure", false, "skip cert verify (dev)")
	flag.Usage = usage
	flag.Parse()

	if flag.NArg() < 1 {
		usage()
	}
	cmd := flag.Arg(0)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	switch cmd {

	case "version":
		fmt.Printf("gk %s (%s)\n", version, buildDate)

	case "register":
		fs := flag.NewFlagSet("register", flag.ExitOnError)
		u := fs.String("u", "", "username")
		p := fs.String("p", "", "password")
		_ = fs.Parse(flag.Args()[1:])
		if *u == "" || *p == "" {
			fmt.Fprintln(os.Stderr, "need -u and -p")
			os.Exit(1)
		}

		cc, cli, err := dial(ctx, *addr, *caPath, *insecure, "")
		if err != nil {
			fail(err)
		}
		defer cc.Close()

		resp, err := cli.Register(ctx, &pb.RegisterRequest{Username: *u, Password: *p})
		if err != nil {
			fail(err)
		}
		fmt.Println(resp.GetUserId())

	case "login":
		fs := flag.NewFlagSet("login", flag.ExitOnError)
		u := fs.String("u", "", "username")
		p := fs.String("p", "", "password")
		_ = fs.Parse(flag.Args()[1:])
		if *u == "" || *p == "" {
			fmt.Fprintln(os.Stderr, "need -u and -p")
			os.Exit(1)
		}

		cc, cli, err := dial(ctx, *addr, *caPath, *insecure, "")
		if err != nil {
			fail(err)
		}
		defer cc.Close()

		resp, err := cli.Login(ctx, &pb.LoginRequest{Username: *u, Password: *p})
		if err != nil {
			fail(err)
		}

		// derive KEK once
		kek := clientcrypto.DeriveKEK([]byte(*p), resp.GetKekSalt())

		if len(resp.GetWrappedDek()) > 0 {
			// unwrap and save DEK
			dek, err := clientcrypto.UnwrapDEK(kek, resp.GetWrappedDek())
			if err != nil {
				fail(fmt.Errorf("unwrap DEK: %w", err))
			}
			if err := saveDEK(dek); err != nil {
				fail(err)
			}
		} else {
			// first login → generate DEK, wrap, push to server, save locally
			dek, err := clientcrypto.Rand(clientcrypto.DEKLen)
			if err != nil {
				fail(err)
			}
			wrapped, err := clientcrypto.WrapDEK(kek, dek)
			if err != nil {
				fail(err)
			}

			cc2, cli2, err := dial(ctx, *addr, *caPath, *insecure, resp.GetAccessToken())
			if err != nil {
				fail(err)
			}
			_, err = cli2.SetWrappedDEK(ctx, &pb.SetWrappedDEKRequest{WrappedDek: wrapped})
			_ = cc2.Close()
			if err != nil {
				fail(err)
			}

			if err := saveDEK(dek); err != nil {
				fail(err)
			}
		}

		// save user id for AAD
		_ = saveUserID(resp.GetUserId())

		// parse exp from JWT
		var claims jwt.RegisteredClaims
		_, _ = jwt.ParseWithClaims(resp.GetAccessToken(), &claims, func(*jwt.Token) (any, error) { return nil, nil },
			jwt.WithoutClaimsValidation(),
		)
		exp := time.Now().Add(15 * time.Minute)
		if claims.ExpiresAt != nil {
			exp = claims.ExpiresAt.Time
		}
		if err := saveToken(resp.GetAccessToken(), exp); err != nil {
			fail(err)
		}

		fmt.Println("ok")

	case "list":
		token, err := loadToken()
		if err != nil {
			fail(err)
		}
		cc, cli, err := dial(ctx, *addr, *caPath, *insecure, token)
		if err != nil {
			fail(err)
		}
		defer cc.Close()

		out, err := cli.GetChanges(ctx, &pb.GetChangesRequest{SinceVer: 0})
		if err != nil {
			fail(err)
		}
		// печатаем коротко
		type row struct{ ID, Ver, Deleted, UpdatedAt string }
		rows := []row{}
		for _, c := range out.GetChanges() {
			rows = append(rows, row{
				ID:        c.GetId(),
				Ver:       fmt.Sprint(c.GetVer()),
				Deleted:   fmt.Sprint(c.GetDeleted()),
				UpdatedAt: tsString(c.GetUpdatedAt()),
			})
		}
		printJSON(rows)

	case "sync":
		fs := flag.NewFlagSet("sync", flag.ExitOnError)
		since := fs.Int64("since", 0, "since version")
		_ = fs.Parse(flag.Args()[1:])

		token, err := loadToken()
		if err != nil {
			fail(err)
		}
		cc, cli, err := dial(ctx, *addr, *caPath, *insecure, token)
		if err != nil {
			fail(err)
		}
		defer cc.Close()

		out, err := cli.GetChanges(ctx, &pb.GetChangesRequest{SinceVer: *since})
		if err != nil {
			fail(err)
		}
		printJSON(out.GetChanges())

	case "get":
		fs := flag.NewFlagSet("get", flag.ExitOnError)
		id := fs.String("id", "", "item id (uuid)")
		_ = fs.Parse(flag.Args()[1:])
		if *id == "" {
			fmt.Fprintln(os.Stderr, "need -id")
			os.Exit(1)
		}

		token, err := loadToken()
		if err != nil {
			fail(err)
		}
		ccConn, cli, err := dial(ctx, *addr, *caPath, *insecure, token)
		if err != nil {
			fail(err)
		}
		defer ccConn.Close()

		out, err := cli.GetItem(ctx, &pb.GetItemRequest{Id: *id})
		if err != nil {
			fail(err)
		}
		if out.GetDeleted() {
			fmt.Fprintln(os.Stderr, "item is deleted")
			os.Exit(1)
		}

		// decrypt: key = HKDF(DEK, itemID); AAD = userID||itemID||ver
		dek, err := loadDEK()
		if err != nil {
			fail(errors.New("no DEK; login first"))
		}
		userID, err := loadUserID()
		if err != nil {
			fail(err)
		}
		ver := out.GetVer()
		blob := out.GetBlobEnc().GetCiphertext()

		key, err := clientcrypto.DeriveItemKey(dek, []byte(*id))
		if err != nil {
			fail(err)
		}
		pt, err := clientcrypto.DecryptBlob(key, []byte(userID), []byte(*id), ver, blob)
		if err != nil {
			fail(fmt.Errorf("decrypt: %w", err))
		}

		// payload формат: {type, meta, data}; печатаем красиво
		var payload struct {
			Type string      `json:"type"`
			Meta interface{} `json:"meta"`
			Data []byte      `json:"data"`
		}
		if err := json.Unmarshal(pt, &payload); err != nil {
			// если не JSON — выведем как есть (hex+size)
			fmt.Printf("id=%s ver=%d at=%s\nraw=%x (%dB)\n",
				out.GetId(), ver, tsString(out.GetUpdatedAt()), pt, len(pt))
			break
		}

		fmt.Printf("id=%s ver=%d at=%s type=%s data=%dB\n",
			out.GetId(), ver, tsString(out.GetUpdatedAt()), payload.Type, len(payload.Data))

		if payload.Meta != nil {
			m, _ := json.MarshalIndent(payload.Meta, "", "  ")
			fmt.Printf("meta=%s\n", m)
		}

	case "add":
		fs := flag.NewFlagSet("add", flag.ExitOnError)
		id := fs.String("id", "", "item id (uuid, optional)")
		typ := fs.String("type", "text", "item type")
		meta := fs.String("meta", "", "meta JSON/string")
		dataFile := fs.String("file", "", "data file ('-'=stdin)")
		_ = fs.Parse(flag.Args()[1:])

		if *id == "" {
			uid, _ := u.NewV4()
			*id = uid.String()
		}
		if *dataFile == "" {
			fmt.Fprintln(os.Stderr, "need -file")
			os.Exit(1)
		}

		token, err := loadToken()
		if err != nil {
			fail(err)
		}
		ccConn, cli, err := dial(ctx, *addr, *caPath, *insecure, token)
		if err != nil {
			fail(err)
		}
		defer ccConn.Close()

		// payload: {type, meta, data}
		data, err := readAll(*dataFile)
		if err != nil {
			fail(err)
		}
		payload := map[string]any{"type": *typ, "meta": *meta, "data": data}
		plain, _ := json.Marshal(payload)

		dek, err := loadDEK()
		if err != nil {
			fail(errors.New("no DEK (login first with wrapped_dek)"))
		}
		userID, err := loadUserID()
		if err != nil {
			fail(err)
		}

		// AAD = user_id || item_id || ver(=base+1). base=0 → ver=1
		aadUser := []byte(userID)
		aadItem := []byte(*id)
		ver := int64(1)

		key, err := clientcrypto.DeriveItemKey(dek, aadItem)
		if err != nil {
			fail(err)
		}
		blob, err := clientcrypto.EncryptBlob(key, aadUser, aadItem, ver, plain)
		if err != nil {
			fail(err)
		}

		req := &pb.UpsertItemsRequest{
			Items: []*pb.UpsertItem{
				{Id: *id, BaseVer: 0, BlobEnc: &pb.EncryptedBlob{Ciphertext: blob}},
			},
		}
		out, err := cli.UpsertItems(ctx, req)
		if err != nil {
			fail(err)
		}
		printJSON(out.GetResults())

	case "edit":
		fs := flag.NewFlagSet("edit", flag.ExitOnError)
		id := fs.String("id", "", "item id (uuid)")
		base := fs.Int64("base", -1, "base version")
		typ := fs.String("type", "text", "item type")
		meta := fs.String("meta", "", "meta JSON/string")
		dataFile := fs.String("file", "", "data file ('-'=stdin)")
		_ = fs.Parse(flag.Args()[1:])
		if *id == "" || *base < 0 || *dataFile == "" {
			fmt.Fprintln(os.Stderr, "need -id -base -file")
			os.Exit(1)
		}

		token, err := loadToken()
		if err != nil {
			fail(err)
		}
		ccConn, cli, err := dial(ctx, *addr, *caPath, *insecure, token)
		if err != nil {
			fail(err)
		}
		defer ccConn.Close()

		data, err := readAll(*dataFile)
		if err != nil {
			fail(err)
		}
		payload := map[string]any{"type": *typ, "meta": *meta, "data": data}
		plain, _ := json.Marshal(payload)

		dek, err := loadDEK()
		if err != nil {
			fail(errors.New("no DEK"))
		}
		userID, err := loadUserID()
		if err != nil {
			fail(err)
		}

		aadUser := []byte(userID)
		aadItem := []byte(*id)
		ver := *base + 1

		key, err := clientcrypto.DeriveItemKey(dek, aadItem)
		if err != nil {
			fail(err)
		}
		blob, err := clientcrypto.EncryptBlob(key, aadUser, aadItem, ver, plain)
		if err != nil {
			fail(err)
		}

		req := &pb.UpsertItemsRequest{
			Items: []*pb.UpsertItem{
				{Id: *id, BaseVer: *base, BlobEnc: &pb.EncryptedBlob{Ciphertext: blob}},
			},
		}
		out, err := cli.UpsertItems(ctx, req)
		if err != nil {
			fail(err)
		}
		printJSON(out.GetResults())

	case "rm":
		fs := flag.NewFlagSet("rm", flag.ExitOnError)
		id := fs.String("id", "", "item id (uuid)")
		base := fs.Int64("base", -1, "base version")
		_ = fs.Parse(flag.Args()[1:])
		if *id == "" || *base < 0 {
			fmt.Fprintln(os.Stderr, "need -id and -base")
			os.Exit(1)
		}

		token, err := loadToken()
		if err != nil {
			fail(err)
		}
		cc, cli, err := dial(ctx, *addr, *caPath, *insecure, token)
		if err != nil {
			fail(err)
		}
		defer cc.Close()

		out, err := cli.DeleteItem(ctx, &pb.DeleteItemRequest{Id: *id, BaseVer: *base})
		if err != nil {
			fail(err)
		}
		printJSON(out.GetResult())

	case "add-login":
		cmdAddLogin(flag.Args()[1:], *addr, *caPath, *insecure)
	case "add-text":
		cmdAddText(flag.Args()[1:], *addr, *caPath, *insecure)
	case "add-card":
		cmdAddCard(flag.Args()[1:], *addr, *caPath, *insecure)
	case "add-binary":
		cmdAddBinary(flag.Args()[1:], *addr, *caPath, *insecure)
	case "add-otp":
		cmdAddOTP(flag.Args()[1:], *addr, *caPath, *insecure)
	case "show":
		cmdShow(flag.Args()[1:], *addr, *caPath, *insecure)
	default:
		usage()
	}
}

// ---- helpers ----

func tsString(ts *timestamppb.Timestamp) string {
	if ts == nil {
		return ""
	}
	return ts.AsTime().UTC().Format(time.RFC3339)
}

func fail(err error) {
	if s, ok := status.FromError(err); ok {
		fmt.Fprintf(os.Stderr, "rpc error: code=%s msg=%s\n", s.Code(), s.Message())
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
