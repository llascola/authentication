---
id: T30
phase: 06-flow-completion
title: RevokeAllExcept — keep the current session on password change
status: todo
branch: phase-06-flow-completion
layer: internal/port, internal/adapter/memory, internal/app
depends_on: []
touches:
  - internal/port/repository.go
  - internal/adapter/memory/store.go
  - internal/app/change_password.go
  - internal/app/change_password_test.go
  - docs/adr/
done_when:
  - SessionRepository gains RevokeAllExcept(ctx, userID, keepTokenHash)
  - in-memory implementation is serialised and race-clean
  - ChangePassword keeps the initiating session, revokes every other
  - ResetPassword still revokes ALL sessions (no session to keep, and the old
    credential is presumed compromised)
  - a superseding ADR records the change to ADR 0015
  - tests assert the initiating session survives and a second session does not
  - make check + make vuln pass
---

# T30 — RevokeAllExcept

## Goal

Stop `ChangePassword` logging the user out of the session they used to change
their password.

## Read this before starting

[ADR 0015](../../adr/0015-http-edge-security-posture.md) decided full revocation
**deliberately**, and its Consequences section names `RevokeAllExcept` as the known
follow-up. So this task is not a bug fix — it reverses a locked decision, and per
`CLAUDE.md` that requires a **new ADR that supersedes the relevant part of 0015**,
not an edit to it. Write the ADR as part of this task ([T32](T32-adrs.md) tracks
the phase's ADRs; this one is specifically a supersede).

The argument for reversing: a voluntary password change from an authenticated
session is not evidence that session is compromised, and logging the user out
mid-action is the kind of friction that trains people to avoid changing passwords.
The argument against — the one 0015 took — is that a password change implies the
old credential may be compromised, so keep nothing. Both are defensible; the ADR
should say why the trade moved, not pretend the old choice was wrong.

## Scope boundary

| Flow | Behaviour after this task |
|------|---------------------------|
| `ChangePassword` (authenticated, knows the old password) | Keep the initiating session, revoke all others |
| `ResetPassword` (via emailed token, does **not** know the old password) | Revoke **all** sessions, unchanged |

Reset must stay all-revoking. Someone resetting via email may be recovering from a
compromise, and there is no "current session" to preserve anyway.

## Steps

1. Extend `port.SessionRepository` with `RevokeAllExcept(ctx, userID, keepTokenHash)`.
   Key on the token **hash**, not a raw token — the raw value must not reach the
   repository ([ADR 0013](../../adr/0013-opaque-token-generation-and-rehash.md)).
2. Thread the current session's hash into `ChangePasswordService`. The handler has
   the cookie; the use-case should receive the already-hashed value.
3. Implement in `internal/adapter/memory/store.go`, serialised like the existing
   revoke-all path ([ADR 0008](../../adr/0008-aggregate-concurrency-contract.md)).
4. Update the port contract test and `change_password_test.go`.
5. Write the superseding ADR.

## Notes

- Interacts with [T29](T29-csrf.md): a preserved session keeps its CSRF token, so
  rotate it on password change rather than leaving a token minted before the
  credential changed.
- Phase 07 will need the same method on the Postgres session repository — the port
  contract test is what keeps the two implementations honest.
