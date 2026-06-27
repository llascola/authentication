---
id: T03
phase: 01-ports
title: TokenGenerator port
status: done
branch: phase-01-ports
layer: internal/port
depends_on: []
touches:
  - internal/port/token_generator.go
  - internal/port/token_generator_test.go
done_when:
  - TokenGenerator interface compiles
  - returns both raw secret (for delivery) and domain.TokenHash (for storage)
  - tests implemented: a test stub satisfies TokenGenerator (compile-time `var _` assertion); GeneratedToken exposes Raw + Hash
  - make check passes (fmt-check, vet, staticcheck, go test -race)
  - make vuln passes
---

# T03 — TokenGenerator port

## Goal

Mint a high-entropy opaque secret and its stored hash in one call. Used for both
session bearer tokens and verification-token secrets.

## Context

- `domain.TokenHash` stores only the hash; raw secret shown/sent once, never
  persisted (see `session.go`, `verification.go`).
- Adapter (T08): `crypto/rand` 32 bytes → base64url raw; SHA-256 → `TokenHash`.

## Interface sketch

```go
type GeneratedToken struct {
    Raw  string            // delivered to client / sent over side channel
    Hash domain.TokenHash  // persisted
}

type TokenGenerator interface {
    Generate(ctx context.Context) (GeneratedToken, error)
}
```

## Steps

1. New file `internal/port/token_generator.go`, package `port`.
2. Define `GeneratedToken` struct + `TokenGenerator` interface.
3. Doc-comment: `Raw` is secret, must never be logged/persisted; only `Hash` is stored.

## Notes

- One generator serves sessions and verification tokens — same entropy needs.
- Hash algorithm (SHA-256) is the adapter's choice; the port is silent on it.
