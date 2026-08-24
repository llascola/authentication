---
id: T28
phase: 06-flow-completion
title: Apply rate limits at the edge
status: todo
branch: phase-06-flow-completion
layer: internal/adapter/http, internal/config, cmd/server
depends_on: [T26, T27]
touches:
  - internal/adapter/http/middleware.go
  - internal/adapter/http/router.go
  - internal/adapter/http/middleware_test.go
  - internal/config/config.go
  - cmd/server/main.go
done_when:
  - login, register, forgot-password, and resend-verification are all limited
  - login is limited per-IP AND per-email, so a spray across accounts is caught
  - over-limit returns 429 with Retry-After and reveals nothing about account state
  - the limit applies identically whether or not the account exists
  - limits are configurable via env with safe defaults
  - tests drive a handler past its limit and assert 429 + header
  - make check + make vuln pass
---

# T28 — Apply rate limits at the edge

## Goal

Put [T27](T27-ratelimiter-port.md)'s limiter in front of the four routes that an
attacker can turn into something expensive.

## What each route is protecting against

| Route | Key | Threat |
|-------|-----|--------|
| `POST /auth/login` | client IP **and** submitted email | Password spraying. Per-account lockout does not catch one guess each against 10,000 accounts — only a per-IP limit does |
| `POST /auth/register` | client IP | Account-creation flood, each one costing a bcrypt hash and an email |
| `POST /auth/password/forgot` | client IP **and** submitted email | Mail bomb at a known address, on your SMTP quota and your domain's sending reputation |
| `POST /auth/verify-email/resend` | client IP **and** submitted email | Same as above |

The per-email key is what makes this more than decoration: it bounds how much mail
any single address can be made to receive, no matter how many IPs ask.

## Enumeration safety — the trap in this task

A limit keyed by email must behave **identically for addresses that do not exist**.
The natural implementation — look the account up, then rate-limit only if found —
turns the limiter into an account-existence oracle: throttled means real,
unthrottled means unknown. Limit first, on the submitted value, before any lookup.

Normalise the email before keying it (the same `port.Normalizer` the use-cases use),
or `User@x.com` and `user@x.com` become separate buckets.

Return the same fixed 429 body everywhere. `Retry-After` is fine to send — it
describes the limiter, not the account.

## Steps

1. Middleware in `middleware.go`: `rateLimit(limiter port.RateLimiter, keyFn func(*http.Request) string)`,
   composed with the existing handler chain.
2. Key extraction: client IP from `RemoteAddr` only — no proxy headers
   ([ADR 0015](../../adr/0015-http-edge-security-posture.md) does not trust them,
   and a spoofable key is not a limit). If a reverse proxy lands in front later,
   trusting `X-Forwarded-For` becomes a deliberate, ADR-recorded change.
3. For per-email keys the middleware must read the body — buffer and restore it so
   the handler can still decode, and keep the existing `MaxBytesReader` limit.
   Alternatively call the limiter inside the handler after decode; simpler, but
   then remember the enumeration rule above.
4. Add `429` to the central error map in `errors.go` rather than writing the status
   inline — that map is the single audited place statuses are assigned.
5. Config: limit + window per policy, env-driven, with defaults that a real user
   will not hit (a person mistyping a password five times must not be locked out
   of the internet).
6. Wire the limiters in `cmd/server`.

## Notes

- Order matters: rate limit **before** the bcrypt comparison, or the limiter is
  protecting the CPU it already spent.
- Login already does a dummy bcrypt for timing equalization. Rejecting at the
  limiter skips that, which is fine — a 429 is not a credential answer.
- Per-process limits only (T27). Two replicas double every limit.
