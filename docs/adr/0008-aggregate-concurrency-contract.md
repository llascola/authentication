# 0008. Aggregates assume serialized read-modify-write

- Status: Accepted
- Date: 2026-06-08

## Context

Domain aggregates (`User`, `Session`, `RecoveryCodeSet`, ...) are
single-threaded consistency boundaries. They do not self-synchronize, and an
aggregate cannot see a concurrent stale copy of itself. Under parallel requests,
a race lives at the `SELECT → mutate → UPDATE` boundary (last-write-wins lost
update). Two of these races are security-relevant, so the persistence/use-case
layer must uphold a clear contract.

## Decision

We state the contract explicitly: **every aggregate mutation runs inside a
serialized read-modify-write (row lock or conditional update). The domain
assumes serialized access.** This is an infrastructure responsibility, not a
domain change.

Strategy is chosen **per hotspot**, not blanket:

- **Lockout bypass (sharpest).** `User.RecordFailedLogin` (threshold 5): N
  concurrent wrong-password attempts each read `failedAttempts=0` and write `1`,
  so the account never locks — brute-force protection defeated by parallelism.
  Fix with a pessimistic `SELECT ... FOR UPDATE` in the login transaction, or an
  atomic SQL `failedAttempts = failedAttempts + 1` with a threshold check. **Not**
  optimistic locking — retry storms happen exactly under attack, because
  contention *is* the attack.
- **Recovery-code double-spend.** `RecoveryCodeSet.Consume` (single-use): two
  requests present the same code, both read it unused, both mark it used, both
  return nil. Fix with a conditional `UPDATE ... WHERE used_at IS NULL`; zero
  rows affected means already spent.
- **Low-contention edits** (profile/roles/MFA): optimistic `version` column.

We will **not** add a `version` field to aggregates globally. A `version int` is
needed only on aggregates chosen for optimistic guarding; pessimistic and
conditional-update paths require zero domain changes. The field is a consequence
of strategy, not a prerequisite.

## Consequences

- The domain stays free of locking/versioning concerns and is simpler to reason
  about.
- The repository/app layer carries real responsibility: getting a hotspot's
  strategy wrong is a security bug (lockout bypass, code reuse), not just a lost
  update.
- Each new mutating use-case must pick and document its concurrency strategy.
- When optimistic locking is later chosen for a specific aggregate, only that
  aggregate gains a `version` field.
