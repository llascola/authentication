# 0018. CSRF: double-submit token bound to the session by HMAC

- Status: Accepted
- Date: 2026-08-23
- Refines: the "SameSite=Lax is a mitigation, not a defence" gap left open in
  [0015](0015-http-edge-security-posture.md)

## Context

The session cookie is the only thing authenticating
`POST /auth/password/change` today. [ADR 0015](0015-http-edge-security-posture.md)
set `SameSite=Lax` and recorded a dedicated CSRF token as future work, because
Lax is a mitigation with known gaps: a same-site attacker (any subdomain that can
set cookies on the parent domain), a browser that treats the attribute loosely,
or a route that later becomes state-changing via `GET`.

The obvious scheme — plain double-submit, where a random cookie must be echoed in
a header — has a matching weakness. It proves only that the sender could *set a
cookie on this domain*. A subdomain attacker can do exactly that, so an unbound
double-submit token fails against the same adversary Lax fails against. The
mitigation and the defence would share one weakness, which is no defence at all.

We also have a constraint from [ADR 0017](0017-keep-initiating-session-on-password-change.md):
the session deliberately survives a password change, and 0017 recorded that the
CSRF token bound to it must then be rotated rather than carried over.

## Decision

We will use double-submit **bound to the session by an HMAC**, verified at the
edge with no stored state.

- On login the server sets `csrf_token`, a cookie that is deliberately **not**
  `HttpOnly` — the frontend has to read it to echo it. It carries no authority
  alone; the session cookie stays `HttpOnly`.
- Token layout: `base64url(nonce) "." base64url(HMAC-SHA256(key, nonce|sessionToken))`,
  with a 16-byte random nonce and a server key from `AUTH_CSRF_KEY`.
- The client echoes the value in `X-CSRF-Token`. A header is the part a
  cross-site form post cannot produce.
- Verification requires **both**: the header equals the cookie
  (`subtle.ConstantTimeCompare`), and the MAC verifies against the presented
  session token (`hmac.Equal`). The second check is what a cookie-setting
  same-site attacker cannot satisfy.
- Applied to `POST /auth/password/change` and `POST /auth/logout`. A request
  carrying **no** session cookie passes through unchecked: there is no ambient
  authority to abuse, and requiring a token would break logout's idempotence.
  Public routes (login, register, forgot, reset, verify, resend) are not covered
  for the same reason — no session exists yet.
- The check sits **outside** `requireAuth`, so a forged request is refused before
  the session lookup and, importantly, before `ValidateSession` slides that
  session's idle window. An attacker must not be able to keep a victim's session
  alive with forged requests.
- Failures are a single fixed `403` through the central error map, saying nothing
  about which of "no token", "wrong token", or "another session's token"
  happened.
- `AUTH_CSRF_KEY` must be at least 32 bytes. Unset yields a random per-process
  key plus a warning; `NewRouter` panics on an empty key.

## Consequences

- A cross-site request cannot mint or read a token, and a same-site
  cookie-setting attacker cannot forge the binding without the server key. That
  is a genuine defence rather than a second copy of the Lax mitigation.
- **Rotation is issuance, not revocation — this is the sharp edge.** Because
  verification is a stateless HMAC, the server keeps no record of which nonce is
  current, so *every token it ever minted for a live session keeps verifying
  until that session ends*. Password change hands the client a fresh token, which
  is what ADR 0017 asked for in spirit, but it does **not** invalidate the token
  minted under the old credential.
  - Residual risk: narrow. A CSRF token is useless without the `HttpOnly` session
    cookie, and the cross-site attacker who needs the token cannot read it. It
    bites only someone who once learned a token value by other means (a log, a
    referrer leak, a past XSS) and can still get the browser to attach the
    session cookie.
  - The proper fix is to rotate the **session bearer token** on credential
    change — keeping the session aggregate alive as ADR 0017 requires, but
    re-keying it, which invalidates everything derived from the old token and
    also closes session-fixation-on-credential-change. That is domain and
    repository work (a `Session` mutator plus a repository re-key), not edge
    work, so it is deliberately not in this ADR.
  - `TestCSRFOldTokenStillVerifiesAfterRotation` pins the current behaviour so
    the limitation cannot be forgotten or silently changed.
- An ephemeral key is acceptable only while sessions are in memory: a restart
  drops sessions and tokens together. Phase 07 makes sessions outlive the
  process, at which point an unset `AUTH_CSRF_KEY` would log everyone out on
  every deploy and break horizontal scaling. The startup warning names this.
- The frontend now has a required step: read `csrf_token` and send it as
  `X-CSRF-Token` on state-changing POSTs, and re-read it after a password change.
- Alternatives rejected: plain double-submit (defeated by the same-site attacker,
  as above); a per-session CSRF secret in the session store (revocable, but puts
  edge concerns in the session aggregate and costs a write per issue); the
  Origin/Referer header check (a useful cheap addition later, but not something
  to rely on alone, since not every client sends them).
