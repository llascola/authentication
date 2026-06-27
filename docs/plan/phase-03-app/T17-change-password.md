---
id: T17
phase: 03-app
title: ChangePassword use-case
status: todo
branch: phase-03-app
layer: internal/app
depends_on: [T06, T07, T11]
touches:
  - internal/app/change_password.go
  - internal/app/change_password_test.go
done_when:
  - verifies current password, validates+screens+hashes new, Rotate()s credential
  - revokes sibling sessions (keep current optional)
  - wrong current password rejected; new password reuse policy decided
  - tests cover happy path + each rejection
  - make check + make vuln pass
---

# T17 — ChangePassword use-case

## Goal

Authenticated password change: prove the old, set a new.

## Context

- `Authenticator.Verify`, `PasswordCredential.Rotate(now, hash)`.
- Same validate→screen→hash pipeline as Register (T12).
- Deferrable past MVP.

## Flow

```
now := clock.Now()
// caller is already authenticated (T15 gave us userID)
cred := credRepo.FindByUserID(ctx, userID)
authenticator.Verify(ctx, cred, []byte(nfc(oldPassword)))   // fail -> ErrAuthFailed
norm := nfc(newPassword)
policy.Validate(norm); screener.Screen(ctx, norm)
ph := domain.NewPasswordHash(hasher.Hash(ctx, norm))
cred.Rotate(now, ph)
credRepo.Update(cred)
sessRepo.RevokeAllForUser(ctx, userID, now, "password changed")   // keep current? see notes
```

## Steps

1. `internal/app/change_password.go`, package `app`.
2. Require a valid current password before any mutation.
3. Reuse the Register validate/screen/hash helper — factor it out so T12/T17/T19
   share one path.
4. Tests: success; wrong current; weak new; (optional) new == old rejection.

## Notes

- **Session policy:** revoke all other sessions on change (recommended) but keep
  the session that initiated the change so the user isn't logged out mid-action.
  Needs the current session id passed in. Decide + document.
- "New must differ from old" is not a domain rule; enforce in app if wanted.
