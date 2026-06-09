# 0003. Two constructors: `New*` validates, `Reconstitute*` trusts

- Status: Accepted
- Date: 2026-06-03

## Context

Aggregates are created in two very different situations: minting brand-new state
in response to a command, and rehydrating already-valid state loaded from
storage. If a single constructor served both, it would either re-run (and
possibly re-fail) validation on trusted data, or skip validation on fresh data.
Aggregate fields are private, so storage adapters need a sanctioned way to
rebuild an instance.

## Decision

We will provide two constructors per aggregate:

- `New<Aggregate>(now, ...)` — builds **fresh** state. Validates every argument,
  stamps timestamps from the injected `now`, returns an error on bad input.
  Application/use-case code uses this when creating new state.
- `Reconstitute<Aggregate>(...)` — **hydrates** an aggregate from storage. Trusts
  its inputs and performs no validation (the data was valid when persisted).
  Storage adapters use this; it takes the stored fields directly, including
  timestamps and optional pointers.

`Reconstitute*` makes defensive copies of any incoming slice/pointer fields so
the hydrated aggregate does not alias caller-owned memory.

## Consequences

- The validation boundary is unambiguous: invariants are enforced once, at
  creation, not re-litigated on every load.
- Storage adapters can rebuild aggregates without exposing fields or duplicating
  invariant logic.
- The two paths must be kept consistent: a new field added to an aggregate has
  to be threaded through both constructors.
- `Reconstitute*` is powerful — it can construct otherwise-illegal states.
  It is intended for trusted persistence code only; application logic must go
  through `New*` and the mutator methods.
