---
id: T08
phase: 02-adapters
title: Token generator adapter
status: done
branch: phase-02-adapters
layer: internal/adapter/crypto
depends_on: [T03]
touches:
  - internal/adapter/crypto/token.go
  - internal/adapter/crypto/token_test.go
done_when:
  - implements port.TokenGenerator
  - 32 bytes from crypto/rand, base64url raw, SHA-256 hash -> domain.TokenHash
  - tests assert uniqueness across calls + raw->hash consistency
  - make check + make vuln pass
---

# T08 — Token generator adapter

## Goal

Implement `port.TokenGenerator` (T03): random secret + its stored hash.

## Context

- Port: [T03](../phase-01-ports/T03-token-generator.md).
- `domain.NewTokenHash([]byte)` wraps the hash.

## Design

```go
type TokenGen struct{}

func (TokenGen) Generate(ctx context.Context) (port.GeneratedToken, error) {
    var b [32]byte
    if _, err := rand.Read(b[:]); err != nil { return port.GeneratedToken{}, err }
    raw := base64.RawURLEncoding.EncodeToString(b[:])
    sum := sha256.Sum256([]byte(raw))
    h, err := domain.NewTokenHash(sum[:])
    return port.GeneratedToken{Raw: raw, Hash: h}, err
}
```

## Steps

1. `internal/adapter/crypto/token.go`, package `crypto` (alongside bcrypt).
2. Implement as above; compile-time `var _ port.TokenGenerator`.
3. Tests: two calls give different Raw + Hash; hashing Raw reproduces Hash.

## Notes

- Hash the **base64 string** (what the client returns), not the raw bytes —
  consistency: validate-session re-hashes the cookie string the same way (T15).
- `crypto/rand.Read` error is fatal entropy failure; propagate, never fall back.
