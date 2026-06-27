# Security Review — Password-Auth Vertical Slice

- Date: 2026-06-27
- Scope: changes on branch `phase-05-verify` (phases 01–05, tasks T01–T24) —
  driven ports, infrastructure adapters, application use-cases, HTTP edge, and
  wiring for the password-credential slice.
- Method: focused security review. Traced every untrusted input path (HTTP
  request bodies, the session cookie, verification/reset tokens) to its sensitive
  sink, compared against the documented ADR posture, and filtered candidate
  findings for false positives.

## Conclusion

**No HIGH or MEDIUM severity vulnerabilities** were found in the newly added code
that meet the review's confidence bar. One candidate was raised and dismissed
(see below). The slice is defensively sound and consistent with its ADRs.

## What was verified

- **Session tokens** — 256-bit `crypto/rand` entropy, base64url raw shown once,
  SHA-256 stored at rest (only the hash persisted). Validation re-hashes the
  presented value and looks up by hash, so there is no secret-comparison timing
  leak. Mint and validate share one recipe (`crypto.TokenGen`, ADR 0013), so they
  cannot drift.
- **Password hashing** — bcrypt with constant-time `CompareHashAndPassword`. The
  SHA-256 base64 prehash defeats bcrypt's 72-byte truncation without entropy loss
  (ADR 0007). NFC normalization is applied to the same form that is validated and
  hashed (ADR 0006/0014), so a password cannot pass checks in one encoding and be
  stored under another.
- **Verification / reset tokens** — single-use (consumed before the mutating
  action, so a replay cannot re-verify or re-reset), purpose-bound (email-verify
  vs password-reset are not interchangeable), domain-enforced expiry, and prior
  unconsumed tokens invalidated per (user, purpose) by the store (ADR 0009/0012).
- **Enumeration safety** — a single central error→status map collapses account
  and token existence into uniform responses: `ErrAuthFailed` /
  `ErrNotAuthenticated` → 401 fixed body; `ErrInvalidToken` → 400; only
  input-quality errors (password policy, malformed email) → 400 with detail.
  Register on a duplicate email and forgot-password on an unknown email return the
  same success-shaped response as the happy path. Login is timing-equalized: the
  missing-account path still runs a dummy bcrypt comparison (ADR 0015).
- **Auth middleware** — no bypass. `requireAuth` resolves the cookie via
  `ValidateSession` and injects the identity into context; every failure
  (missing/unknown/revoked/expired) is a fail-closed 401.
- **Session cookie** — `HttpOnly`, `Secure` (default on; off only via explicit
  `AUTH_COOKIE_SECURE=false` for local http), `SameSite=Lax`, `Path=/`,
  `Max-Age` = absolute TTL; cleared on logout.
- **Credential change** — ChangePassword and ResetPassword revoke all of the
  user's sessions (ResetPassword unconditionally; ChangePassword including the
  initiating session), so a rotated credential leaves no live session behind.
- **Injection surface** — none introduced. No SQL, templates, shell, or
  deserialization. JSON only, size-limited (`MaxBytesReader`), unknown fields
  rejected (`DisallowUnknownFields`). No proxy headers trusted; client IP from
  `RemoteAddr` only.

## Candidate considered and dismissed

**Raw verification/reset tokens written to logs** — `internal/adapter/mailer/log.go`
logs the raw token as a structured field, wired unconditionally in
`cmd/server/main.go`. A reset token is a high-value bearer secret, so in a real
deployment this would be account-takeover material for anyone with log-read
access.

Dismissed as not an actionable finding on this PR: `LogMailer` is an explicitly
and loudly documented **DEV-ONLY placeholder** (package doc: "production mailer
MUST NOT log the raw token — this exists only because the slice has no real email
transport yet"). The slice has no production composition root and no real mailer;
the stub exists precisely so the integration test can read the token a user would
receive by email. This is a known-placeholder / hardening gap, not a concrete
shipped vulnerability, and exploitation presupposes log-read access. Filtered
confidence: 3/10.

## Non-blocking notes (follow-ups before any non-dev deployment)

- **Swap the dev placeholders.** Replace `mailer.LogMailer` with a real mailer
  that never logs the token, and `screener.NoOp` (which accepts every password,
  including breached) with a real breach screener. Prefer a composition root that
  fails closed if either is left unconfigured. Both are documented placeholders.
- **CSRF + rate-limiting.** A dedicated CSRF token on state-changing POSTs and
  rate-limiting on login / forgot-password are recorded as future work in
  ADR 0015. `SameSite=Lax` covers the realistic cross-site POST vector in the
  interim.
- **Keep `AUTH_COOKIE_SECURE=true`** in any environment reachable over the
  network; the `false` affordance is for local http only.
- **Session-revocation strictness.** ChangePassword currently revokes the
  initiating session too (logs the user out mid-action). This is a deliberate,
  secure default; relaxing it to keep the current session needs a
  revoke-all-except-current repository method (ADR 0015).
