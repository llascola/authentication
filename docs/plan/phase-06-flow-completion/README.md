# Phase 06 — Flow completion + edge hardening

**Layer:** `internal/port`, `internal/adapter`, `internal/app`, `internal/adapter/http` ·
**Branch:** `phase-06-flow-completion` · **Depends on:** Phase 05.

The password slice proved the flow works. This phase closes the gaps that stop it
being *usable* by a real person and *safe* to expose to the internet.

## Why these, and in this order

Two of the gaps are functional dead-ends, not polish:

- **No resend-verification.** A verification token lives 24h. If the mail is lost,
  bounces, or the send fails after the user row is committed, the account is stuck
  `pending` forever: login refuses it, re-registering returns enumeration-safe
  success without minting a token, and a reset token is the wrong purpose. That
  address becomes permanently unusable with no recovery path at any layer.
- **No rate limiting.** Beyond password spraying (per-account lockout does not
  catch a spray across many accounts), an unthrottled `/auth/password/forgot`
  lets anyone pump unlimited mail through the SMTP account at any registered
  address — burning quota and sending reputation.

They ship together on purpose: a resend endpoint without a rate limit is a mail
cannon pointed at your own domain.

## Scope

| Task | What |
|------|------|
| [T25](T25-resend-verification.md) | ResendVerification use-case |
| [T26](T26-resend-endpoint.md) | `POST /auth/verify-email/resend` |
| [T27](T27-ratelimiter-port.md) | `port.RateLimiter` + in-memory adapter |
| [T28](T28-apply-rate-limits.md) | Apply limits at the edge, 429 + `Retry-After` |
| [T29](T29-csrf.md) | CSRF token for cookie-authenticated POSTs |
| [T30](T30-revoke-all-except.md) | `RevokeAllExcept` so a password change keeps the current session |
| [T31](T31-hibp-screener.md) | Real breach screener (HIBP k-anonymity) |
| [T32](T32-adrs.md) | ADRs for the decisions this phase locks |

## Exit criteria

- A user who never received the verification mail can recover without operator help.
- Login, register, forgot, and resend are all rate-limited, and the limit reveals
  nothing about whether an account exists.
- Cookie-authenticated state-changing POSTs require a CSRF token.
- Every decision this phase locks has an ADR (T32).
- `make check` + `make vuln` pass.

## Current task

→ **T25**. T27 can run in parallel; T28 needs both.

## Explicitly not here

Postgres persistence is [Phase 07](../phase-07-persistence/). Everything in this
phase still runs against the in-memory store, so a restart still wipes state —
that is the next phase's problem, not this one's.
