---
id: T18
phase: 03-app
title: ForgotPassword use-case
status: done
branch: phase-03-app
layer: internal/app
depends_on: [T06, T08, T09]
touches:
  - internal/app/forgot_password.go
  - internal/app/forgot_password_test.go
done_when:
  - issues a PurposePasswordReset token + mails it, for a known account
  - unknown email returns the SAME result (enumeration-safe), no token issued
  - prior unconsumed reset tokens invalidated on issue (ADR 0009, via repo)
  - tests cover known + unknown email identical externally
  - make check + make vuln pass
---

# T18 — ForgotPassword use-case

## Goal

Start the password-reset flow: mint a reset token and email it. Reveal nothing
about whether the email is registered.

## Context

- `domain.NewVerificationToken(now, userID, PurposePasswordReset, hash)` (1h TTL).
- Token invalidation on issue: repo contract from [ADR 0009](../../adr/0009-cross-aggregate-uniqueness-constraints.md).
- Deferrable past MVP.

## Flow

```
now := clock.Now()
user, err := userRepo.FindByEmail(ctx, email)
if err != nil { return nil }                  // unknown email: silently succeed, no leak
tok := tokenGen.Generate(ctx)
vt := domain.NewVerificationToken(now, user.ID(), domain.PurposePasswordReset, tok.Hash)
vtRepo.Create(vt)                              // invalidates prior unconsumed reset tokens
mailer.SendPasswordReset(ctx, email, tok.Raw)
return nil                                     // always the same outward result
```

## Steps

1. `internal/app/forgot_password.go`, package `app`.
2. Always return success-shaped output regardless of account existence.
3. Tests: known email issues + mails a token; unknown email issues nothing but
   returns identically; re-request invalidates the previous token.

## Notes

- Consider rate-limiting per email/IP — out of slice scope, note for later.
- Keep timing roughly equal between known/unknown branches if feasible.
