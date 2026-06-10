# 0009. Cross-aggregate uniqueness and constraints enforced by the repository

- Status: Accepted
- Date: 2026-06-09

## Context

Domain aggregates reference one another by ID and never embed a sibling, so an
aggregate can be loaded and mutated in isolation (ADR 0001, ADR 0008). A direct
consequence: an aggregate cannot see its siblings, so any rule that spans rows or
aggregates — uniqueness, "at most one active per key", replace-on-write — is
*inexpressible* in the domain. The domain already acknowledges this in one place
(`verification.go`: the "≤1 active token per (userID, purpose)" TODO).

These rules still have to hold. They are the contract the `internal/port`
repository interfaces and their adapters must honour. This ADR catalogues the
full set in one place so the rules do not fragment across adapters, and records
the product decisions behind the soft ones. It is the reference for the ports
layer; the matching `Err*` conflict sentinels will be defined in `internal/port`
beside the repository interfaces (not yet present — `internal/port` currently
holds only the `Authenticator` port).

## Decision

### Hard invariants (structural — always enforced)

| Invariant | Scope | Enforcement | Conflict error |
|---|---|---|---|
| `User.email` unique (normalized) | global | unique index on lowercased email (`NewEmail` already lowercases) | `ErrEmailTaken` |
| OAuth `(provider, subject)` unique | global | unique index — the pair *is* the foreign identity | `ErrOAuthSubjectLinked` |
| `WebAuthnID` unique | global | unique index — login lookup handle | `ErrWebAuthnIDTaken` |
| `Session.tokenHash` unique | global | unique index — lookup key | `ErrSessionTokenTaken` |
| `VerificationToken.tokenHash` unique | global | unique index — lookup key | `ErrVerificationTokenTaken` |
| ≤1 `PasswordCredential` per user | per user | unique index on `user_id` in the password-credential table; `Rotate` mutates, never inserts a second | `ErrPasswordCredentialExists` |

### Product decisions (policy — chosen here)

- **Email is reserved after deactivation.** `Deactivated` is terminal
  (`user.go` `allowedTransitions`); rows are not deleted, so the global email
  unique index already covers deactivated accounts and the address can never be
  re-registered. No tombstone table needed. *Rationale: blocks identity reuse and
  re-registration takeover of a closed account.*

- **Phone is unique among verified numbers.** Phone backs SMS OTP and account
  recovery, so two accounts must not share a *verified* number (that would share
  a second factor). Unverified collisions are allowed (typos, pending verify).
  Enforcement: partial unique index on the phone column `WHERE phone_verified`.
  Conflict error `ErrPhoneTaken`, raised at verify time, not at set time.

- **One OAuth account per provider per user.** A user links at most one Google,
  one GitHub, etc. Enforcement: unique index on `(user_id, provider)` in the
  oauth-credential table. This is independent of, and additional to, the global
  `(provider, subject)` uniqueness above. Conflict error `ErrOAuthProviderLinked`.

- **Multiple OTP authenticators per user allowed.** No per-user uniqueness on
  OTP credentials; a user may register several confirmed TOTP authenticators,
  consistent with multi-key WebAuthn. Nothing to enforce here — recorded so the
  absence of a constraint is deliberate.

### Stateful "≤1 active per key" rules

- **VerificationToken: ≤1 active per `(userID, purpose)`** (the existing TODO).
  Active = unconsumed and unexpired; expiry is time-derived and cannot live in an
  index. Enforcement: on issue, invalidate any prior unconsumed token for the
  same `(userID, purpose)` in the same transaction, backed by a partial unique
  index `WHERE consumed_at IS NULL`. Expired-but-unconsumed rows are swept or
  invalidated on the next issue rather than blocking issuance.

- **RecoveryCodeSet: ≤1 set per user**, regeneration replaces
  (`recovery.go`: "regenerating is a brand-new set; the repo replaces the old
  one"). Enforcement: unique index on `user_id`; regenerate deletes the old set
  and inserts the new one in a single transaction.

### Enforcement discipline

Adapters enforce via the database constraint and translate the unique-violation
(e.g. Postgres SQLSTATE `23505`) into the typed `Err*` conflict sentinel —
**insert-and-catch, never check-then-insert**. A read-then-write uniqueness check
races under concurrency; the constraint is the only authority. This is the same
serialization contract as ADR 0008: correctness comes from the store, not from an
in-memory check.

## Consequences

- The repository port interfaces return typed conflict errors the application
  maps to user-facing responses; callers use `errors.Is`, matching the domain's
  sentinel convention.
- Each constraint is a concrete schema obligation (unique or partial-unique
  index) plus, for the two stateful rules, a same-transaction
  invalidate/replace step.
- Login flows that must not disclose existence (e.g. signup revealing a taken
  email) decide at the application layer how much of a conflict to surface; the
  repository still reports it precisely.
- Adding a new credential kind or purpose forces a revisit of this table — its
  uniqueness story is not automatic.
- The `verification.go` TODO is now resolved *by contract*; the code comment can
  point here.
