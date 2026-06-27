---
id: T12
phase: 03-app
title: Register use-case
status: todo
branch: phase-03-app
layer: internal/app
depends_on: [T06, T07, T08, T09, T10, T11]
touches:
  - internal/app/register.go
  - internal/app/register_test.go
done_when:
  - validates policy, screens breach, hashes, creates User+PasswordCredential atomically
  - issues email-verify token + sends via mailer
  - duplicate email returns an enumeration-safe result
  - tests cover happy path + each rejection
  - make check + make vuln pass
---

# T12 — Register use-case

## Goal

Create a new pending identity with a password credential and kick off email
verification.

## Context

- Atomicity + uniqueness: [ADR 0009](../../adr/0009-cross-aggregate-uniqueness-constraints.md).
- Normalization: [ADR 0006](../../adr/0006-password-length-and-unicode.md) — app does NFC.
- Ports: T01 repos, T02 hasher, T03 token gen, T05 mailer, T04 clock, screener.

## Flow

```
now := clock.Now()
norm := nfc(plaintext)                       // app normalizes (precompose)
policy.Validate(norm)                        // domain.DefaultPasswordPolicy
screener.Screen(ctx, norm)                   // port; no-op for slice
email := domain.NewEmail(rawEmail)
hashBytes := hasher.Hash(ctx, norm)
ph := domain.NewPasswordHash(hashBytes)
user := domain.NewUser(now, email)           // pending
cred := domain.NewPasswordCredential(now, user.ID(), ph)
-- atomic: userRepo.Create(user) + credRepo.Create(cred)   // rollback on dup email
tok := tokenGen.Generate(ctx)
vt := domain.NewVerificationToken(now, user.ID(), domain.PurposeEmailVerify, tok.Hash)
vtRepo.Create(vt)
mailer.SendEmailVerification(ctx, email, tok.Raw)
```

## Steps

1. `internal/app/register.go`, package `app`. Define a `RegisterService` struct
   holding the port deps; constructor injects them.
2. Implement the flow above. Zero the plaintext after hashing; never store it.
3. On duplicate email (`port.ErrEmailTaken`): return success-shaped response (or a
   neutral error the HTTP layer renders identically) — do not leak existence.
4. Atomicity: with the in-memory store, wrap user+cred create so a failure on the
   second rolls back the first (delete the user), or add a small store method that
   does both under one lock. Document the choice.
5. Tests with in-memory store + fakes: happy path; weak password; bad email;
   duplicate email; mailer error path.

## Notes

- NFC: use `golang.org/x/text/unicode/norm` (`norm.NFC.String`). Adds a dep —
  confirm it is acceptable or do minimal normalization. Flag in T24/ADR if needed.
- Decide response shape: return `UserID` + "verification sent", or nothing.
- The transient plaintext lives only in this function; never passes to a domain entity.
