---
id: T15
phase: 03-app
title: ValidateSession use-case
status: done
branch: phase-03-app
layer: internal/app
depends_on: [T06, T10]
touches:
  - internal/app/validate_session.go
  - internal/app/validate_session_test.go
done_when:
  - hashes presented token, finds session, checks IsActive, Touches it
  - revoked/expired/unknown rejected
  - returns the authenticated UserID (+ AAL) for downstream use
  - tests cover active, idle-expired, revoked, unknown
  - make check + make vuln pass
---

# T15 — ValidateSession use-case

## Goal

Turn a presented session token (from the cookie) into an authenticated identity,
sliding the idle window. This is the middleware behind "GET /me" and any
protected route.

## Context

- `Session.IsActive`, `Session.Touch` (session.go).
- Token hashing recipe must match T08/T13.

## Flow

```
now := clock.Now()
hash := sha256(rawCookieToken)
sess := sessRepo.FindByTokenHash(ctx, hash)   // unknown -> ErrNotAuthenticated
if !sess.IsActive(now) { -> ErrNotAuthenticated }
sess.Touch(now)                                // slides idle expiry
sessRepo.Update(sess)
return sess.UserID(), sess.AuthLevel()
```

## Steps

1. `internal/app/validate_session.go`, package `app`.
2. Single `ErrNotAuthenticated` for unknown/revoked/expired.
3. `Touch` returns an error on revoked/expired — treat as not-authenticated.
4. Tests: active session validates + slides; past idle deadline fails; revoked
   fails; unknown hash fails.

## Notes

- Decide whether every request `Update`s (writes lastSeen each call) or throttles
  the touch (only if idle window moved materially). For the slice, write each time
  — simplest, correct.
- Return enough for AuthZ-less "who am I": UserID + AAL. Roles are read live from
  the User elsewhere, never snapshotted in the session (see session.go doc).
