---
id: T07
phase: 02-adapters
title: bcrypt hasher + authenticator
status: done
branch: phase-02-adapters
layer: internal/adapter/crypto
depends_on: [T02]
touches:
  - internal/adapter/crypto/bcrypt.go
  - internal/adapter/crypto/bcrypt_test.go
  - go.mod
done_when:
  - implements port.PasswordHasher and port.Authenticator
  - prehash recipe base64(sha256(pw)) -> bcrypt (ADR 0007)
  - Verify is constant-time via bcrypt.CompareHashAndPassword
  - round-trip + wrong-password tests pass
  - golang.org/x/crypto added; make check + make vuln pass
---

# T07 — bcrypt hasher + authenticator

## Goal

Both sides of password crypto: `Hash(plaintext) -> bytes` (T02 port) and
`Verify(cred, presented)` (existing `port.Authenticator`).

## Context

- Recipe: [ADR 0007](../../adr/0007-password-hashing-prehash-bcrypt-argon2id.md).
- Ports: [T02](../phase-01-ports/T02-password-hasher.md), `internal/port/authenticator.go`.
- bcrypt 72-byte truncation note: [memory password-hashing].

## Design

```go
// prehash defeats bcrypt's 72-byte input cap without losing entropy.
func prehash(pw string) []byte {
    sum := sha256.Sum256([]byte(pw))
    b64 := base64.StdEncoding.EncodeToString(sum[:]) // 44 bytes < 72
    return []byte(b64)
}

type Bcrypt struct{ cost int } // default bcrypt.DefaultCost

func (b Bcrypt) Hash(ctx, plaintext) ([]byte, error)            // bcrypt.GenerateFromPassword(prehash(pw), cost)
func (b Bcrypt) Type() domain.CredentialType                    // CredentialPassword
func (b Bcrypt) Verify(ctx, cred domain.Credential, presented []byte) error
```

`Verify`: type-assert `cred.(*domain.PasswordCredential)`, get `Hash().Bytes()`,
`bcrypt.CompareHashAndPassword(stored, prehash(string(presented)))`. Map a
mismatch to a single non-distinct error so callers stay enumeration-safe.

## Steps

1. `go get golang.org/x/crypto/bcrypt`; keep `go.mod` tidy.
2. `internal/adapter/crypto/bcrypt.go`, package `crypto`.
3. Implement `prehash`, `Hash`, `Type`, `Verify`. Compile-time `var _ port.PasswordHasher`,
   `var _ port.Authenticator`.
4. Tests: hash→verify round-trip; wrong password rejected; same plaintext hashes
   to different bcrypt outputs (salt); >72-byte password still works (prehash proof).

## Notes

- Cost configurable (T21 config) but default `bcrypt.DefaultCost` for the slice.
- NFC normalization is the **app's** job before calling Hash/Verify (ADR 0006) —
  this adapter assumes normalized input.
- Wrong-password error must be indistinct from not-found upstream (T14).
