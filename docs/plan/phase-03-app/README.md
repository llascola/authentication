# Phase 03 — Application Use-Cases

**Layer:** `internal/app` · **Branch:** `phase-03-app` · **Depends on:** Phase 02.

Orchestrate the domain through the ports. Use-cases depend on port *interfaces*,
never on adapters — so they are testable with fakes and the in-memory store.
This layer owns the transient plaintext password: validate → screen → hash →
discard. The plaintext never enters a domain entity.

## Scope

| Task | What | Key domain calls |
|------|------|------------------|
| [T12](T12-register.md) | Register | `PasswordPolicy.Validate`, `NewUser`, `NewPasswordCredential`, `NewVerificationToken` |
| [T13](T13-verify-email.md) | VerifyEmail | `VerificationToken.Consume`, `User.VerifyEmail` |
| [T14](T14-login.md) | Login | `User.IsLocked`, `Authenticator.Verify`, `Record*Login`, `NewSession` |
| [T15](T15-validate-session.md) | ValidateSession | `Session.IsActive`, `Session.Touch` |
| [T16](T16-logout.md) | Logout | `Session.Revoke` |
| [T17](T17-change-password.md) | ChangePassword | `Authenticator.Verify`, `PasswordCredential.Rotate` |
| [T18](T18-forgot-password.md) | ForgotPassword | `NewVerificationToken` (reset) |
| [T19](T19-reset-password.md) | ResetPassword | `VerificationToken.Consume`, `Rotate`, revoke sessions |

## Cross-cutting rules

- **Enumeration safety:** Login and ForgotPassword reveal nothing about whether
  an email/account exists; a locked account reads as bad credentials.
- **Atomicity:** Register creates User + PasswordCredential together
  ([ADR 0009](../../adr/0009-cross-aggregate-uniqueness-constraints.md)).
- Pull `now` from the `Clock` port once per request; pass into every domain call
  ([ADR 0002](../../adr/0002-inject-clock-via-now-parameter.md)).

## Exit criteria

- Each use-case has happy-path + rejected-input tests with fakes/in-memory store.
- `make check` + `make vuln` pass.

## Current task

→ **T14 Login** is the spine; T12 Register feeds it. Recommended order:
T12 → T13 → T14 → T15 → T16, then T17–T19.
