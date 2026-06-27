---
id: T02
phase: 01-ports
title: PasswordHasher port
status: todo
branch: phase-01-ports
layer: internal/port
depends_on: []
touches:
  - internal/port/password_hasher.go
  - internal/port/password_hasher_test.go
done_when:
  - PasswordHasher interface compiles
  - doc comment states prehash recipe is the adapter's job, not the port's
  - tests implemented: a test stub satisfies PasswordHasher (compile-time `var _ port.PasswordHasher` assertion)
  - make check passes (fmt-check, vet, staticcheck, go test -race)
  - make vuln passes
---

# T02 — PasswordHasher port

## Goal

The **produce** side of password crypto: plaintext → hash bytes. The existing
`port.Authenticator` is the **verify** side. Together they bracket the bcrypt
adapter (T07).

## Context

- Hashing recipe: [ADR 0007](../../adr/0007-password-hashing-prehash-bcrypt-argon2id.md) — base64(sha256(pw)) → bcrypt.
- Domain wrapper: `domain.NewPasswordHash([]byte)` guarantees non-empty; the hash
  bytes the adapter returns get wrapped there by the app (T12).
- Why a port: hashing is I/O-free but infra crypto + needs a swappable cost param.

## Interface sketch

```go
type PasswordHasher interface {
    // Hash returns the encoded hash for a (already NFC-normalized) plaintext.
    // The adapter owns the prehash + bcrypt cost; callers treat the result as opaque.
    Hash(ctx context.Context, plaintext string) ([]byte, error)
}
```

## Steps

1. New file `internal/port/password_hasher.go`, package `port`.
2. Define `PasswordHasher`. Keep it 1 method; verification stays on `Authenticator`.
3. Doc-comment: plaintext must be NFC-normalized by the caller (ADR 0006); the
   port says nothing about algorithm — that is T07.

## Notes

- `ctx` included for symmetry/future cost-tuning even though bcrypt is CPU-bound.
  Acceptable; drop it if it reads as noise.
- No sentinel errors expected; bcrypt failure is an infra error.
