---
id: T14
phase: 03-app
title: Login use-case
status: todo
branch: phase-03-app
layer: internal/app
depends_on: [T06, T07, T08, T10]
touches:
  - internal/app/login.go
  - internal/app/login_test.go
done_when:
  - gates on Status + IsLocked, verifies password, records success/failure
  - issues an AAL1 session (amr=pwd) with token cookie value
  - all failure modes return one indistinct error (enumeration-safe)
  - tests cover success, bad password, locked, unverified/inactive, lockout trip
  - make check + make vuln pass
---

# T14 — Login use-case

## Goal

Authenticate email + password and issue a session. The spine of the slice.

## Context

- Lockout: `User.IsLocked`, `RecordFailedLogin`, `RecordSuccessfulLogin` (user.go).
- Session: `domain.NewSession(now, userID, tokenHash, AAL1, []AuthMethod{AuthMethodPassword}, device, idleTTL, absTTL)`.
- Enumeration safety: [phase-03 README](README.md) cross-cutting rules.

## Flow

```
now := clock.Now()
user := userRepo.FindByEmail(ctx, email)      // not found -> generic fail (still do a dummy hash compare to equalize timing)
if user.Status() != Active || user.IsLocked(now) { -> generic fail }   // never disclose which
err := authenticator.Verify(ctx, cred, []byte(nfc(password)))
if err != nil {
    user.RecordFailedLogin(now); userRepo.Update(user); -> generic fail
}
user.RecordSuccessfulLogin(now); userRepo.Update(user)
tok := tokenGen.Generate(ctx)
sess := domain.NewSession(now, user.ID(), tok.Hash, domain.AAL1, []domain.AuthMethod{domain.AuthMethodPassword}, device, idleTTL, absTTL)
sessRepo.Create(sess)
return tok.Raw   // set as cookie by HTTP layer (T20)
```

## Steps

1. `internal/app/login.go`, package `app`. Inject repos, authenticator, token gen,
   clock, and the TTL config.
2. Single sentinel `ErrAuthFailed` for every failure branch (bad email, bad
   password, locked, inactive) — the HTTP layer renders one 401.
3. Timing: when the user is missing, still run a bcrypt compare against a dummy
   hash so response time doesn't reveal account existence.
4. Load the `PasswordCredential` via `credRepo.FindByUserID`; pass to `Verify`.
5. Build `DeviceInfo` from request (ip/ua) — passed in by caller.
6. Tests: success; wrong password (counter increments); 5th failure locks; locked
   account; pending/suspended account; deactivated.

## Notes

- Pull idle/abs TTL from config (T21); domain validates `idleTTL <= absoluteTTL`.
- Do NOT `Touch` here — `NewSession` already stamps lastSeen; Touch is for T15.
- amr/AAL is password-only AAL1; MFA step-up is out of slice scope.
