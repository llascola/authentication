---
id: T16
phase: 03-app
title: Logout use-case
status: done
branch: phase-03-app
layer: internal/app
depends_on: [T06, T10]
touches:
  - internal/app/logout.go
  - internal/app/logout_test.go
done_when:
  - revokes the session for a presented token
  - idempotent / safe on unknown or already-revoked token
  - tests cover active revoke + already-revoked
  - make check + make vuln pass
---

# T16 — Logout use-case

## Goal

Revoke the current session.

## Context

- `Session.Revoke(now, reason)` → `ErrSessionNotActive` if not active.

## Flow

```
now := clock.Now()
hash := sha256(rawCookieToken)
sess := sessRepo.FindByTokenHash(ctx, hash)   // unknown -> treat as success (already gone)
sess.Revoke(now, "user logout")               // already revoked -> swallow
sessRepo.Update(sess)
```

## Steps

1. `internal/app/logout.go`, package `app`.
2. Make it idempotent: unknown token or `ErrSessionNotActive` → return nil (the
   client is logged out either way). HTTP layer clears the cookie regardless.
3. Tests: active session revoked; second logout is a no-op success.

## Notes

- Reason string is for audit; keep it stable ("user logout").
- "Log out everywhere" = `RevokeAllForUser` (T01) — optional, can ride on T17/T19.
