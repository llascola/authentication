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

→ none. T25–T32 are all `done`; the phase is complete. Next is
[Phase 07](../phase-07-persistence/), starting at T33.

Decisions this phase locked are ADRs [0017](../../adr/0017-keep-initiating-session-on-password-change.md)
through [0021](../../adr/0021-rate-limiting-shape-and-policy.md).

Four things were deliberately left open rather than silently dropped, all
recorded where they will be found again:

- The CSRF token cannot be *revoked*, only reissued — closing that means
  re-keying the session bearer token on credential change, which is domain and
  repository work ([ADR 0018](../../adr/0018-csrf-double-submit-bound-to-session.md),
  pinned by `TestCSRFOldTokenStillVerifiesAfterRotation`). Phase 07 rewrites the
  session repository anyway, so that is the natural place for it.
- Breach screening is off by default (`AUTH_PASSWORD_SCREENER=noop`) so CI stays
  offline, which means ADR 0011's trade is unmet until a deployment turns it on.
  Startup logs a warning saying so.
- Login's per-email rate-limit key lets anyone knowing an address hold that
  account's login at `429`. `Limits.Login` is one limiter instance serving both
  the IP and email keys, so the two cannot be tuned apart; splitting them is the
  fix ([ADR 0021](../../adr/0021-rate-limiting-shape-and-policy.md) consequences).
- Rate limiting bounds mail to a registered *address*, not to a *mailbox*:
  registration mails arbitrary addresses under an IP-only key, and subaddressing
  gives one mailbox unlimited distinct keys. Bounding it means limiting account
  creation itself — a product decision, not a limiter tweak (ADR 0021).

## Explicitly not here

Postgres persistence is [Phase 07](../phase-07-persistence/). Everything in this
phase still runs against the in-memory store, so a restart still wipes state —
that is the next phase's problem, not this one's.
