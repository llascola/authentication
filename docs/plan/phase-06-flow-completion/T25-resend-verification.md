---
id: T25
phase: 06-flow-completion
title: ResendVerification use-case
status: done
branch: phase-06-flow-completion
layer: internal/app
depends_on: [T13]
touches:
  - internal/app/resend_verification.go
  - internal/app/resend_verification_test.go
done_when:
  - a pending, unverified account gets a fresh PurposeEmailVerify token, mailed
  - unknown email, already-verified, and terminal-status accounts all return the
    SAME result, issuing nothing (enumeration-safe)
  - issuing invalidates any prior unconsumed verify token (ADR 0009, via repo)
  - tests cover all four branches and assert they are externally identical
  - make check + make vuln pass
---

# T25 — ResendVerification use-case

## Goal

Give a user whose verification mail never arrived a way to get a new one, without
leaking which addresses are registered.

## Why this is not optional

Trace the current dead-end:

1. Verify tokens live 24h (`domain.ttlByPurpose`, [ADR 0005](../../adr/0005-verification-token-one-aggregate-purpose-enum.md)).
2. Mail is lost or bounces — or `SendEmailVerification` fails, which happens
   *after* the user, credential, and token are already committed
   (`internal/app/register.go`, mailer call is the last statement).
3. Login refuses the account: it requires `StatusActive`.
4. Re-registering hits `port.ErrEmailTaken`, which `Register` maps to `nil` for
   enumeration safety — no new token is minted.
5. Forgot-password issues a `PurposePasswordReset` token; `VerifyEmail` rejects a
   wrong-purpose token.

Net: the address is permanently unusable and nothing in the system can fix it.

## Flow

```
now := clock.Now()
email, err := domain.NewEmail(rawEmail)
if err != nil { return nil }                   // malformed: no leak, nothing issued
user, err := userRepo.FindByEmail(ctx, email)
if err != nil { return nil }                   // unknown: no leak, nothing issued
if user.EmailVerified() { return nil }         // already done: no leak, no mail
if user.Status() != domain.StatusPending { return nil }  // terminal/locked: nothing
tok := tokenGen.Generate(ctx)
vt := domain.NewVerificationToken(now, user.ID(), domain.PurposeEmailVerify, tok.Hash)
vtRepo.Create(vt)                              // invalidates prior unconsumed verify tokens
mailer.SendEmailVerification(ctx, email, tok.Raw)
return nil                                     // always the same outward result
```

Mirror `ForgotPasswordService` exactly — same shape, same enumeration discipline.
Check the domain for the real predicate names before writing (`EmailVerified()`
may be spelled differently); the flow above is the intent, not a literal.

## Steps

1. `internal/app/resend_verification.go`, package `app`.
2. Constructor takes only the ports it needs: users, tokens, mailer, tokenGen, clock.
3. Tests: pending+unverified mails a token; unknown / already-verified / non-pending
   each issue nothing and return identically; re-request invalidates the prior token.
4. Wire into `httpapi.Deps` and `cmd/server` — the endpoint itself is [T26](T26-resend-endpoint.md).

## Notes

- **Must** be rate-limited before it ships ([T28](T28-apply-rate-limits.md)).
  Unthrottled, this is an open relay for mail at any registered address, on your
  SMTP quota and your domain's reputation.
- A per-user cooldown (e.g. one resend per 60s) is worth considering *in addition*
  to the edge limit, since the edge limit is keyed by IP. Decide in [T32](T32-adrs.md).
- Does not fix the underlying "state committed before mail sent" ordering in
  Register — it is the escape hatch for it. An outbox/retry is a later question.
