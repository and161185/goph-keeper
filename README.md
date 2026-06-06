# GophKeeper

GophKeeper is a backend-focused training project for secure client-server storage of confidential data: logins, passwords, text notes, binary files, card data, and OTP secrets.

All item encryption is performed on the client side. The server stores only encrypted payloads and service metadata. The project includes item-level versioning, tombstones, and a basic GetChanges API as synchronization primitives, but it is not a full production-grade synchronization system.

This is a backend-focused training project. The CLI is a demo client for testing the API, encryption flow, and synchronization logic. It is not a full-featured password manager UI.

## Features

* gRPC over TLS
* Registration and login with JWT HS256
* PostgreSQL storage
* Item-level versioning with optimistic concurrency
* Tombstones as deletion markers
* Basic GetChanges API as a synchronization primitive
* Optimistic concurrency with `base_ver`
* Client-side crypto: XChaCha20-Poly1305 AEAD, DEK/KEK, Argon2id, HKDF per-item key
* AAD binding: `user_id || item_id || ver`
* CLI demo client with typed commands: `add-login`, `add-text`, `add-card`, `add-binary`, `add-otp`, `show`
* OTP secret storage, without TOTP code generation on the client
* Binary uploads limited to 1 MiB per RPC on the server side
* Structured logging, gRPC interceptors, and health check

## Security model

* Password hash: `pwd_hash = Argon2id(password, salt_auth)`
* The server stores only password hash and salt, not plaintext passwords.
* The DEK is generated on the client.
* The KEK is derived from the user password and `kek_salt`.
* The server stores the DEK only as `wrapped_dek`, encrypted by the KEK.
* Item payloads are encrypted with XChaCha20-Poly1305.
* AAD includes `user_id`, `item_id`, and item version.

## Limitations

* This is a training project, not a production-ready password manager.
* The CLI stores the DEK locally in a file with `0600` permissions; OS keychain integration is not implemented.
* Refresh tokens are present in the API model, but refresh flow is not implemented.
* gRPC metrics are not implemented; only logging and health check are available.
* The CLI code is intentionally simple and not deeply split into packages.
* GetChanges is simplified: it uses item-level versions and should not be treated as production-grade delta synchronization. A real sync model would need a global change sequence, a change log, or another explicit sync design.

## Documentation

Additional documentation:

* [Architecture](docs/architecture.md)

## Requirements

* Go 1.24.5+
* Docker Compose
* OpenSSL for generating local development certificates
* PostgreSQL, if running the server without Docker Compose

## Quickstart

### 1. Generate local TLS certificate

For local development, generate a self-signed certificate in the project root:

```bash
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout key.pem \
  -out cert.pem \
  -days 365 \
  -subj "/CN=localhost"
```

The Docker Compose setup mounts these files into the server container.

### 2. Start server with Docker Compose

```bash
# migrations are applied automatically with goose and embedded SQL files
docker compose up --build
```

The server listens on `localhost:8443`.

### 3. Build CLI

```bash
go build -o bin/gk ./cmd/cli
```

### 4. Register and login

```bash
# first login initializes wrapped_dek
./bin/gk -addr localhost:8443 -insecure register -u user -p qwe123
./bin/gk -addr localhost:8443 -insecure login    -u user -p qwe123
```

### 5. Add demo data

```bash
# Note: all add-* commands accept --note for arbitrary metadata encrypted on the client.
./bin/gk -addr localhost:8443 -insecure add-login  --title "GitHub" --url https://github.com --username me --password secret --note "work account"
./bin/gk -addr localhost:8443 -insecure add-text   --title "Note"   --text "hello"                                           --note "draft"
./bin/gk -addr localhost:8443 -insecure add-card   --title "Visa"   --name "A User" --number 4111111111111111 --exp 12/30 --cvc 123 --note "personal"
./bin/gk -addr localhost:8443 -insecure add-binary --title "Pic"    --file ./photo.jpg                                      --note "avatar"
./bin/gk -addr localhost:8443 -insecure add-otp    --title "Google" --issuer ACME --secret JBSWY3DPEHPK3PXP --digits 6 --period 30 --note "2FA"
```

### 6. List and show items

```bash
# list item ids and versions
./bin/gk -addr localhost:8443 -insecure list

# show decrypted metadata only
./bin/gk -addr localhost:8443 -insecure show -id <id>

# explicitly reveal secret payload data
./bin/gk -addr localhost:8443 -insecure show -id <id> -reveal
```

By default, `show` prints decrypted metadata and secret payload size, but does not print secret data.

For card records, metadata contains only non-sensitive display fields such as title and last four card digits. Full card data is printed only with `-reveal`.

For binary records, `show` does not write binary data to stdout by default. Use `-out` to restore the file:

```bash
./bin/gk -addr localhost:8443 -insecure show -id <id> -out ./restored-file.bin
```

To intentionally write binary data to stdout:

```bash
./bin/gk -addr localhost:8443 -insecure show -id <id> -out -
```

## Local server run

If PostgreSQL is already running locally, the server can also be started without Docker Compose:

```bash
# migrations are applied automatically with goose and embedded SQL files
go run ./cmd/server \
  -dev \
  -dsn "postgres://gk:gkpass@localhost:5432/gk?sslmode=disable" \
  -jwt-key "supersecret" \
  -tls-cert cert.pem \
  -tls-key key.pem
```

## TLS notes: -insecure

The CLI uses TLS when connecting to the server.

In development with self-signed certificates, pass `-insecure` to skip certificate verification. The connection is still encrypted, but the certificate is not verified.

Do not use `-insecure` in production.

Production options:

* use a certificate trusted by the operating system;
* use a corporate CA;
* pass a custom CA certificate with `-cacert`.

## Configuration

Server flags:

* `-addr`, default `:8443`
* `-dsn`, PostgreSQL DSN
* `-jwt-key`, HS256 signing key, required
* `-tls-cert`, TLS certificate path
* `-tls-key`, TLS private key path
* `-access-ttl`, default `15m`
* `-max-batch`, default `1000`
* `-dev`, enables gRPC reflection

CLI flags:

* `-addr`, server address, default `localhost:8443`
* `-cacert`, custom CA certificate path
* `-insecure`, skip certificate verification for local development

## Build

```bash
# compile both binaries with version and buildDate ldflags
make build

# local release artifacts
make release-local
```

Manual build:

```bash
go build -o bin/gk-server ./cmd/server
go build -o bin/gk ./cmd/cli
```

## Notes for reviewers

The project demonstrates backend implementation details rather than a complete end-user product.

The most important parts are:

* gRPC API design;
* TLS setup;
* JWT authentication;
* PostgreSQL repositories;
* optimistic concurrency;
* delta synchronization;
* client-side encryption flow;
* error mapping to gRPC status codes;
* server startup and graceful shutdown.
