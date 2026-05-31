# Architecture

## Overview

GophKeeper is a backend-focused training project for secure storage and synchronization of confidential data.

The project focuses on gRPC communication, TLS, JWT authentication, PostgreSQL storage, optimistic concurrency, delta synchronization, and client-side encryption.

This is a training project, not a production-ready password manager.

## Components

The system consists of two main components:

* CLI demo client
* gRPC server

The demo client is responsible for encryption and decryption. The server stores only encrypted item payloads and related metadata.

```text
CLI client
  |
  | gRPC over TLS
  v
gRPC server
  |
  v
Service layer
  |
  v
Repository layer
  |
  v
PostgreSQL
```

## Client responsibilities

The CLI client is responsible for:

* user registration and login;
* storing the access token locally;
* deriving the KEK from the user password;
* creating or unwrapping the DEK;
* deriving per-item encryption keys;
* encrypting item payloads before sending them to the server;
* decrypting item payloads received from the server.

The server does not receive plaintext item data.

## Server responsibilities

The server is responsible for:

* handling gRPC requests;
* authenticating users;
* issuing and validating JWT access tokens;
* applying login rate limiting;
* storing encrypted item blobs;
* checking item versions;
* storing tombstones for deleted items;
* returning item changes for synchronization.

## Storage model

PostgreSQL is used as the main storage.

The server stores users, encrypted item blobs, item versions, update timestamps, and deletion markers.

Each item belongs to one user. Each item has a version number that is increased on every update or delete operation.

Updates and deletes use optimistic concurrency. The client sends the version it has seen as `base_ver`. If `base_ver` does not match the current item version, the server returns a version conflict.

## Encryption model

Encryption is performed on the client side.

The user password is used to derive a KEK using Argon2id. The KEK is used to unwrap the DEK. The DEK is then used to derive per-item keys using HKDF.

Item payloads are encrypted with XChaCha20-Poly1305.

```text
password
  |
  v
KEK = Argon2id(password, kek_salt)
  |
  v
DEK = unwrap(wrapped_dek, KEK)
  |
  v
item_key = HKDF(DEK, item_id)
  |
  v
encrypted_blob = XChaCha20-Poly1305(item_key, payload, AAD)
```

AAD contains:

```text
user_id || item_id || version
```

This binds the encrypted payload to a specific user, item, and version.

## Payload model

Before encryption, the CLI wraps each typed record into a JSON payload:

```json
{
  "type": "login|text|card|binary|otp",
  "meta": {},
  "data": {}
}
```

`meta` contains non-sensitive display metadata.

`data` contains the secret or binary payload. Passwords, full card numbers, CVC codes, OTP secrets, text bodies, and binary file bytes belong to `data`, not to `meta`.

The demo CLI treats `meta` as safe to display by default. Secret payload data is revealed only by explicit user action.

## Synchronization model

The client can request changes after a known version.

The server returns items with versions greater than the requested version. Deleted items are returned as tombstones.

This allows the client to synchronize incrementally instead of downloading all items every time.

## Error handling

The service uses domain-level sentinel errors for expected cases such as unauthorized access, version conflicts, rate limiting, duplicate usernames, and missing items.

The gRPC layer maps these errors to stable gRPC status codes.

Unexpected errors are returned as internal errors and logged on the server side.

## Observability

The server uses structured logging and gRPC interceptors for request logging and panic recovery.

A gRPC health service is registered.

Metrics are not implemented in this project. In a production version, I would add per-method request counters, latency histograms, error counters, and basic PostgreSQL-related metrics.

## Limitations

* Local DEK storage uses a file with restricted permissions, not an OS keychain.
* Refresh token flow is not implemented.
* gRPC metrics are not implemented.
* CLI code is intentionally simple and not deeply split into packages.
* The CLI focuses on API and encryption flow demonstration rather than full end-user UX.
* There is no advanced multi-device conflict resolution beyond optimistic concurrency.
* This project was built for learning and demonstration, not for production use.
