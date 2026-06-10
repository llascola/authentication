# 0010. Account lifecycle: status transitions, lockout policy, role set

- Status: Proposed
- Date: 2026-06-09

## Context

`User` carries three coupled product decisions that were implemented inline with
only local comments, so the "why" was not reconstructable from the repo:

- the **status lifecycle** and its allowed-transition table
  (`user.go` `allowedTransitions`);
- the **lockout policy** magnitudes (`maxFailedLogins = 5`,
  `lockoutDuration = 15m`); ADR 0008 owns the *concurrency* of the lockout
  counter but never justified the numbers;
- the **role set** (`RoleUser`, `RoleAdmin`) shipped on a server whose ADR 0001
  scope is explicitly authentication-only, with authorization out of scope —
  which reads as a contradiction until the reasoning is written down.

These are policy choices, not mechanics; a reader needs the rationale to know
whether a change (a new status edge, a different threshold, a third role) is a
bug or a deliberate evolution. This ADR records them in one place.

## Decision

### Status lifecycle

A `User` moves through four states with this transition table (`user.go`):

```
Pending     -> Active, Deactivated
Active       -> Suspended, Deactivated
Suspended    -> Active, Deactivated
Deactivated  -> (terminal)
```

Rules and rationale:

- **`Pending` is the unverified birth state.** A fresh `NewUser` is `Pending`;
  first email verification promotes it to `Active` (`VerifyEmail`). There is no
  `Pending -> Suspended` edge: suspending an account that was never usable is
  meaningless — close it (`Deactivated`) instead.
- **`Suspended` is a reversible admin block; `Deactivated` is terminal.** This is
  the core distinction: suspension is a temporary hold an admin can lift
  (`Suspended -> Active`), deactivation is account closure and has no outgoing
  edges. Lockout (below) is a *third*, separate notion and never changes
  `Status` — a locked account stays `Active`.
- **Every state can reach `Deactivated`.** Closure is always available.
- **No return to `Pending`.** Verification is a one-way gate; an account never
  becomes "unverified" again. Re-verification of a *changed* email is modelled by
  the `emailVerified` flag (`ChangeEmail` resets it), not by a status change.
- **Terminal means terminal.** `ensureNotTerminal` rejects all identity, contact,
  role, and MFA mutations on a `Deactivated` user; only `transition` is exempt,
  and it has no legal target from `Deactivated`. This pairs with ADR 0009: the
  email of a deactivated account stays in the unique index, so the address is
  reserved forever and cannot be re-registered.

### Lockout policy

- **Threshold: 5 consecutive failed logins.** `lockoutDuration: 15 minutes`,
  fixed window, auto-expiring; a successful login resets the counter
  (`RecordSuccessfulLogin`).
- **Rationale.** 5/15m is a deliberately conventional brute-force speed bump
  (the OWASP-style "lock after a handful of attempts for a short cool-off"),
  chosen to blunt online guessing without making a forgotten password a
  long denial of service for the legitimate user. It is *not* the primary
  password-strength defence — that is length + hashing (ADR 0006, ADR 0007).
- **Self-extending under attack, never disclosed.** `RecordFailedLogin` is
  intentionally unguarded against an already-locked account (it re-locks at a
  fresh, later deadline), and the login use-case treats "locked" identically to
  "bad credentials" so the lock is never revealed (no user enumeration). See the
  method comment and ADR 0008 for the concurrency contract on the counter.
- **Values are policy, not invariants.** They are unexported constants today; if
  they ever need to be tunable per deployment they become configuration threaded
  in by the application layer, not a domain change.

### Role set

- **Two roles ship in the domain: `RoleUser` (default) and `RoleAdmin`.** A user
  always holds at least one role: `NewUser` defaults to `{RoleUser}` and
  `RemoveRole` refuses to remove the last one (`ErrCannotRemoveLastRole`), so the
  consuming authorization layer never sees a roleless user.
- **Why roles exist here at all, given AuthN-only scope (ADR 0001).** Roles are a
  *carried claim*, not an authorization decision. The server stores and exposes
  them (read live off `User`, never snapshotted into a `Session`) so a future
  external PDP has something to read; this server never evaluates them. Keeping
  the claim here does not pull authorization into scope.
- **Why exactly these two.** `user`/`admin` is the minimal pair that exercises
  the role machinery (default assignment, add/remove, last-role guard) without
  inventing an authorization taxonomy this server has no business owning. The set
  is deliberately small and is expected to be replaced or extended once a real
  PDP defines the actual taxonomy — at which point its source of truth may move
  out of this server entirely.

## Consequences

- The three policy clusters now have a written rationale; a change to the
  transition table, the lockout numbers, or the role set is a conscious revisit
  of this ADR, not an unexplained edit.
- The status table is small and closed; adding a state or an edge means updating
  `allowedTransitions`, its tests, and this ADR together.
- Lockout magnitudes are documented as conventional and tunable-by-config-later;
  no domain change is implied by retuning them.
- The role set is explicitly provisional. When the external PDP lands, expect a
  superseding ADR that redefines or relocates roles; code must keep reading roles
  live (never cache them in a session) so that move stays cheap.
