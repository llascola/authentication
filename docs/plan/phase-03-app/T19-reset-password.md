---
id: T19
phase: 03-app
title: ResetPassword use-case
status: todo
branch: phase-03-app
layer: internal/app
depends_on: [T06, T07, T11]
touches:
  - internal/app/reset_password.go
  - internal/app/reset_password_test.go
done_when:
  - consumes a PurposePasswordReset token, rotates the hash, revokes all sessions
  - validates+screens new password
  - expired/consumed/wrong-purpose token rejected
  - tests cover happy path + each rejection
  - make check + make vuln pass
---

# T19 — ResetPassword use-case

## Goal

Finish the reset flow: consume the token, set a new password, kill all sessions.

## Context

- `VerificationToken.Consume`, `PasswordCredential.Rotate`, `RevokeAllForUser`.
- Same validate→screen→hash pipeline as T12/T17.
- Deferrable past MVP.

## Flow

```
now := clock.Now()
hash := sha256(rawToken)
vt := vtRepo.FindByTokenHash(ctx, hash)        // unknown -> neutral error
// confirm purpose == PurposePasswordReset
vt.Consume(now)                                 // single-use + expiry
vtRepo.Update(vt)
norm := nfc(newPassword); policy.Validate(norm); screener.Screen(ctx, norm)
cred := credRepo.FindByUserID(ctx, vt.UserID())
cred.Rotate(now, domain.NewPasswordHash(hasher.Hash(ctx, norm)))
credRepo.Update(cred)
sessRepo.RevokeAllForUser(ctx, vt.UserID(), now, "password reset")
```

## Steps

1. `internal/app/reset_password.go`, package `app`.
2. Consume token before rotating, so a replay can't reset twice.
3. Reuse the shared validate/screen/hash helper (T12/T17).
4. Revoke **all** sessions — a reset implies possible compromise, no session kept.
5. Tests: success; expired token; reused token; wrong purpose; weak new password.

## Notes

- Unlike ChangePassword, no current-session exemption: reset revokes everything.
- A successful reset on a still-pending account could also verify the email
  (proves channel control) — decide; out of strict scope, note it.
