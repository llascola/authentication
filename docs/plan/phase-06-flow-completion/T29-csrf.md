---
id: T29
phase: 06-flow-completion
title: CSRF token for cookie-authenticated POSTs
status: done
branch: phase-06-flow-completion
layer: internal/adapter/http
depends_on: []
touches:
  - internal/adapter/http/middleware.go
  - internal/adapter/http/handlers.go
  - internal/adapter/http/router.go
  - internal/adapter/http/middleware_test.go
done_when:
  - state-changing POSTs behind requireAuth require a valid CSRF token
  - token is issued on login and rotated on privilege change
  - comparison is constant-time; a missing or mismatched token is a fixed 403
  - tests cover valid, missing, mismatched, and cross-session tokens
  - make check + make vuln pass
---

# T29 — CSRF token for cookie-authenticated POSTs

## Goal

Close the gap [ADR 0015](../../adr/0015-http-edge-security-posture.md) left open:
`SameSite=Lax` is a mitigation, not a defence.

## Why Lax is not enough

`SameSite=Lax` stops cross-site *POSTs* from carrying the cookie, which covers the
common case. It does not cover: a same-site attacker (any subdomain that can set
cookies on the parent domain), a browser that treats the attribute loosely, or a
future route that becomes state-changing via `GET`. The cookie is the only thing
authenticating `POST /auth/password/change` today.

## Scheme

Double-submit with a signed token is the usual fit for a stdlib server:

- On login, issue a random token in a **non-HttpOnly** cookie (the frontend must
  read it) bound to the session — e.g. HMAC over the session id with a server key.
- The frontend echoes it in an `X-CSRF-Token` header on state-changing requests.
- Middleware compares header against cookie with `crypto/subtle.ConstantTimeCompare`,
  and verifies the binding so a token from another session is rejected.

Decide the exact scheme in [T32](T32-adrs.md); the binding to the session is the
part that must not be skipped — an unbound double-submit token is defeated by any
attacker who can set a cookie on the domain.

## Which routes

- **Required**: `POST /auth/password/change` — behind `requireAuth`, cookie-authenticated.
- **Consider**: `POST /auth/logout`. Forced logout is a nuisance, not a breach, but
  it is trivially covered by the same middleware.
- **Not applicable**: login, register, forgot, reset, verify, resend. No session
  exists yet, so there is no ambient authority to abuse.

## Steps

1. Token minting + cookie set alongside the session cookie on login.
2. `requireCSRF` middleware, composed with `requireAuth` on the routes above.
3. Rotate the token whenever the session changes (login, and after a password change
   that issues a new session).
4. `403` through the central map in `errors.go`, fixed body.
5. Tests: valid passes; missing header, mismatched value, and a token minted for a
   different session each 403.

## Notes

- The CSRF cookie is deliberately readable by JS — that is the mechanism, not a bug.
  It carries no authority on its own; the session cookie stays `HttpOnly`.
- Interacts with [T30](T30-revoke-all-except.md): if a password change now preserves
  the current session, the CSRF token bound to it must be rotated, not reused.
