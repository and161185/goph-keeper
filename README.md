# GophKeeper

Client–server system for secure storage and synchronization of confidential data (logins, passwords, text, binary files, card data). **All encryption is performed on the client.**

## Features

* gRPC over TLS
* Registration & login (JWT HS256)
* Versioning, tombstones, delta sync
* Client‑side crypto: XChaCha20‑Poly1305 (AEAD), DEK/KEK (Argon2id), HKDF per‑item key, AAD = `user_id || item_id || ver`
* CLI with typed commands: `add-login`, `add-text`, `add-card`, `add-binary`, `add-otp`, `show`
* OTP: store TOTP secrets (no code generation on client)
* Binary uploads limited to 1 MiB per RPC (server receive).

## Security model (brief)

* Password hash: `pwd_hash = Argon2id(password, salt_auth)` (server stores only hash + salt)
* Data key DEK (32 bytes) is generated on the client; KEK = Argon2id(password, `kek_salt`)
* Server keeps DEK only as `wrapped_dek` (AEAD under KEK)
* Records are encrypted with XChaCha20‑Poly1305; AAD includes `user_id`, `item_id`, and version

## Requirements

* Go 1.24.5+
* PostgrSQL 14+
* (dev) self‑signed certs `cert.pem` / `key.pem`

## Quickstart

### Server

```bash
# migrations are applied automatically (goose + embed)
go run ./cmd/server \
  -dev \
  -dsn "postgres://gk:gkpass@localhost:5432/gk?sslmode=disable" \
  -jwt-key "supersecret" \
  -tls-cert cert.pem \
  -tls-key key.pem
```

### CLI

```bash
# build
go build -o bin/gk ./cmd/cli

# registration & login (first login initializes wrapped_dek)
./bin/gk -addr localhost:8443 -insecure register -u alice -p qwe123
./bin/gk -addr localhost:8443 -insecure login    -u alice -p qwe123

# examples
# Note: all add-* commands accept --note for arbitrary metadata (encrypted on the client).
./bin/gk -addr localhost:8443 -insecure add-login  --title "GitHub" --url https://github.com --username me --password secret --note "work account"
./bin/gk -addr localhost:8443 -insecure add-text   --title "Note"   --text "hello"                                           --note "draft"
./bin/gk -addr localhost:8443 -insecure add-card   --title "Visa"   --name "A User" --number 4111111111111111 --exp 12/30 --cvc 123 --note "personal"
./bin/gk -addr localhost:8443 -insecure add-binary --title "Pic"    --file ./photo.jpg                                      --note "avatar"
./bin/gk -addr localhost:8443 -insecure add-otp    --title "Google" --issuer ACME --secret JBSWY3DPEHPK3PXP --digits 6 --period 30 --note "2FA"
./bin/gk -addr localhost:8443 -insecure show -id <uuid>
```
## TLS notes: -insecure

The CLI uses TLS when connecting to the server. In development with self‑signed certificates you can pass -insecure to skip certificate verification (the connection is still encrypted, but the certificate is not verified). This is convenient for local testing, but do not use in production.

Production options:

Use a certificate trusted by your OS (public CA or your corporate CA).

Or provide a custom CA bundle to the CLI (implementing a -ca flag or placing the CA in the system trust store).

## Configuration

Server flags / environment variables:

* `-addr` (`GK_ADDR`, default `:8443`)
* `-dsn` (`GK_PG_DSN`) — PostgreSQL DSN
* `-jwt-key` (`GK_JWT_KEY`) — HS256 key
* `-tls-cert`, `-tls-key` (`GK_TLS_CERT`, `GK_TLS_KEY`)
* `-access-ttl` (default 15m)
* Login rate limiter: `-lim-window` (15m), `-lim-max` (5), `-lim-block` (15m)

## Build

```bash
# compile both binaries with version/buildDate ldflags
make build        # -> bin/gk-server, bin/gk

# local release artifacts (no cross-compilation)
make release-local  # -> dist/
