# 0012. Repository port contract: sentinel not-found, adapter-side constraints, copy-on-store

- Status: Accepted
- Date: 2026-06-27

## Context

The password slice needed persistence interfaces (T01) for four aggregates:
User, PasswordCredential, Session, VerificationToken. Several contract questions
had to be answered once, uniformly, so every adapter and every caller agrees:

- How does a lookup report "nothing found" — a sentinel error, or `(nil, nil)`?
- Where do cross-aggregate rules live — unique email, and "only the newest
  unconsumed verification token per (user, purpose) is valid" (ADR 0009)?
- Where does the read-modify-write serialization the aggregates assume
  (ADR 0008) get enforced?
- The in-memory adapter (T06) hands out aggregate pointers; how do we stop a
  caller mutating stored state through a retained reference?

## Decision

We will define the repository ports in `internal/port` with these contracts:

- **Not-found is a sentinel error**, never `(nil, nil)`. Each port declares
  `Err*NotFound` (prefixed `port: `) plus conflict sentinels `ErrEmailTaken` and
  `ErrCredentialExists`. Callers branch with `errors.Is`.
- **Constraints live in the adapter, behind the port.** `UserRepository.Create`
  enforces email uniqueness; `VerificationTokenRepository.Create` invalidates the
  prior unconsumed token for the same (user, purpose). The port documents the
  behaviour; the interface signature stays minimal.
- **Serialization is the adapter's concern.** The port says nothing about row
  locks or optimistic versions; an in-memory mutex satisfies it. No
  `expectedVersion` argument leaks into the interface.
- **The store keeps copies, not caller pointers.** The in-memory adapter
  deep-copies aggregates via the domain `Reconstitute*` constructors on every
  read and write, so a caller cannot mutate stored state through a retained
  pointer and two readers never share a mutable aggregate.

## Consequences

- Callers get a single, predictable miss signal and never nil-check an aggregate
  against a nil error. Enumeration-safe use-cases map these sentinels centrally.
- Swapping the in-memory store for a database changes only the adapter; the port
  and every use-case are untouched. The constraint and serialization mechanisms
  move to SQL (unique index, partial index, row lock) without touching callers.
- Copy-on-store cost is real but bounded and correct; it also forced one missing
  domain getter (`Session.IdleTTL`) so the round-trip is faithful through the
  public API.
- `RevokeAllForUser` lives on `SessionRepository` rather than being composed from
  a find-loop in the app — simpler for the slice; revisit if a find-active query
  is needed elsewhere.
