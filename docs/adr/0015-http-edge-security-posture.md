# 0015. HTTP edge security posture: cookies, enumeration safety, timing, session revocation

- Status: Accepted
- Date: 2026-06-27

## Context

The HTTP edge (T20) and the use-cases behind it (T12–T19) make several
security-weighted choices that need to be settled and visible, because they are
the difference between an authentication server that leaks and one that does not.
They span the cookie, the error surface, login timing, and what a password change
does to existing sessions.

## Decision

- **Session cookie.** The session bearer token is delivered in a cookie that is
  `HttpOnly` (no JS access), `Secure` (HTTPS-only; configurable off only for
  local http dev via `AUTH_COOKIE_SECURE=false`), `SameSite=Lax` (blunts CSRF on
  cross-site POSTs while allowing top-level navigation), `Path=/`, with
  `Max-Age` = the absolute session TTL. Logout clears it (`Max-Age` < 0).
- **Enumeration safety, enforced centrally.** A single error→status map is the
  only place statuses are assigned. `ErrAuthFailed`/`ErrNotAuthenticated` → 401
  with a fixed body, so "no such account", "wrong password", "locked", and "no
  session" are indistinguishable. Register on a duplicate email and
  forgot-password on an unknown email return the *same* success response as the
  happy path (the use-cases return nil, issuing nothing). Only input-quality
  errors (password policy, malformed email) surface as 400 with detail, since
  they describe the submitted payload, not account state.
- **Login timing equalization.** When no account or credential matches, login
  still runs a bcrypt comparison against a lazily-built dummy hash of the
  configured cost, so response time does not reveal whether an email is
  registered.
- **Full session revocation on credential change.** Both ChangePassword and
  ResetPassword revoke *all* of the user's sessions, including the one that
  initiated the change. A password change implies the old credential may be
  compromised; no session is kept.
- **Edge hardening.** Request bodies are size-limited (`MaxBytesReader`) with
  unknown JSON fields rejected. No proxy headers are trusted; the client IP comes
  from `RemoteAddr` only.

## Consequences

- The auth API reveals nothing about account or token existence through status
  codes, bodies, or timing — the property the central map keeps auditable.
- Revoking the initiating session on ChangePassword logs the user out mid-action;
  this is a deliberate strictness trade-off. Keeping the current session would
  need a `RevokeAllExcept` repository method (the current token hash threaded
  through) — out of slice scope, recorded here as the known follow-up.
- `SameSite=Lax` is a CSRF mitigation, not a complete defense; a dedicated CSRF
  token for state-changing POSTs is future work. Rate-limiting login and
  forgot-password (per IP/email) is also deferred and noted.
- The dummy-hash path assumes the configured bcrypt cost matches real
  credentials' cost; if cost is raised, existing hashes keep their embedded cost
  and timing equalization stays approximate.
