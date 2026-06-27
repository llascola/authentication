---
id: T01
phase: 01-ports
title: Repository ports
status: done
branch: phase-01-ports
layer: internal/port
depends_on: []
touches:
  - internal/port/repository.go
  - internal/port/repository_test.go
done_when:
  - 4 repository interfaces compile, import domain only
  - uniqueness + serialization contracts documented in doc comments
  - tests implemented: port_test fakes satisfy each interface (compile-time `var _` assertions); sentinel errors (ErrUserNotFound/ErrEmailTaken/...) are distinct, non-nil, and prefixed `port: `
  - make check passes (fmt-check, vet, staticcheck, go test -race)
  - make vuln passes
---

# T01 — Repository ports

## Goal

Declare the persistence interfaces the app needs for the password slice. No
implementations (that is T06).

## Context

- Layering: [ADR 0001](../../adr/0001-strict-authn-only-ddd-layering.md) — port imports domain, never reverse.
- Uniqueness/constraints: [ADR 0009](../../adr/0009-cross-aggregate-uniqueness-constraints.md).
- Concurrency: [ADR 0008](../../adr/0008-aggregate-concurrency-contract.md) — repos serialize read-modify-write.
- Existing port style: `internal/port/authenticator.go`, `internal/port/password_screener.go`.

## Interface sketch

```go
type UserRepository interface {
    Create(ctx context.Context, u *domain.User) error          // fails on duplicate email (ADR 0009)
    Update(ctx context.Context, u *domain.User) error          // RMW-serialized (ADR 0008)
    FindByID(ctx context.Context, id domain.UserID) (*domain.User, error)
    FindByEmail(ctx context.Context, email domain.Email) (*domain.User, error)
}

type PasswordCredentialRepository interface {
    Create(ctx context.Context, c *domain.PasswordCredential) error
    Update(ctx context.Context, c *domain.PasswordCredential) error
    FindByUserID(ctx context.Context, id domain.UserID) (*domain.PasswordCredential, error)
}

type SessionRepository interface {
    Create(ctx context.Context, s *domain.Session) error
    Update(ctx context.Context, s *domain.Session) error
    FindByTokenHash(ctx context.Context, h domain.TokenHash) (*domain.Session, error)
    RevokeAllForUser(ctx context.Context, id domain.UserID, now time.Time, reason string) error
}

type VerificationTokenRepository interface {
    // Create invalidates prior unconsumed tokens for (userID, purpose) (ADR 0009).
    Create(ctx context.Context, t *domain.VerificationToken) error
    Update(ctx context.Context, t *domain.VerificationToken) error
    FindByTokenHash(ctx context.Context, h domain.TokenHash) (*domain.VerificationToken, error)
}
```

## Steps

1. New file `internal/port/repository.go`, package `port`.
2. Define the 4 interfaces above; refine method set as use-cases demand (keep minimal).
3. Declare port-level sentinel errors callers branch on: `ErrUserNotFound`,
   `ErrEmailTaken`, `ErrSessionNotFound`, `ErrTokenNotFound` (prefix `port: `).
   Decide: not-found as error vs `(nil, nil)` — pick error + sentinel, document it.
4. Doc-comment the ADR 0009 uniqueness + ADR 0008 serialization contracts on the
   relevant methods.

## Notes / decisions to make

- Not-found contract (sentinel vs nil) — lock it here, all repos follow.
- Whether `RevokeAllForUser` lives on the repo or is composed in the app from a
  `FindActiveByUser` + loop. Repo method is simpler for the slice.
- Optimistic version vs row-lock is an *adapter* concern; the port stays silent
  on it unless an `expectedVersion` arg is needed (in-memory mutex needs none).
- Candidate for an ADR (see T24).
