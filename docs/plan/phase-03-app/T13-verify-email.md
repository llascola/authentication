---
id: T13
phase: 03-app
title: VerifyEmail use-case
status: done
branch: phase-03-app
layer: internal/app
depends_on: [T06, T10]
touches:
  - internal/app/verify_email.go
  - internal/app/verify_email_test.go
done_when:
  - matches token by hash, Consume()s it, promotes pending user to active
  - expired/consumed/unknown token rejected
  - tests cover happy path + each rejection
  - make check + make vuln pass
---

# T13 — VerifyEmail use-case

## Goal

Consume an email-verification token and mark the user's email verified (which
promotes pending → active in the domain).

## Context

- `VerificationToken.Consume`, `User.VerifyEmail` (pending→active side effect).
- Token hashing must match T08 (hash the raw string the user presents).

## Flow

```
now := clock.Now()
hash := sha256(rawToken)                      // same recipe as T08
vt := vtRepo.FindByTokenHash(ctx, hash)       // unknown -> neutral error
// confirm purpose == PurposeEmailVerify
vt.Consume(now)                               // single-use + expiry enforced
vtRepo.Update(vt)
user := userRepo.FindByID(ctx, vt.UserID())
user.VerifyEmail(now)                          // -> active
userRepo.Update(user)
```

## Steps

1. `internal/app/verify_email.go`, package `app`.
2. Re-hash the presented raw token the same way the generator did (centralize that
   helper so T08/T13/T15 agree — consider a small `hashToken(raw)` in the crypto adapter
   exposed via a port method, or duplicate the 3-line recipe with a shared const).
3. Reject wrong purpose, expired, already-consumed, unknown — map to neutral errors.
4. Tests: happy path (pending→active); expired token; reused token; wrong purpose.

## Notes

- Order: Consume the token before mutating the user, so a replay can't re-verify.
- `User.VerifyEmail` returns `ErrEmailAlreadyVerified` if already done — treat as
  idempotent success or surface gently.
