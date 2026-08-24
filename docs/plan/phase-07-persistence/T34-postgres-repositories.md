---
id: T34
phase: 07-persistence
title: Postgres repository adapters
status: todo
branch: phase-07-persistence
layer: internal/adapter/postgres
depends_on: [T33]
touches:
  - internal/adapter/postgres/store.go
  - internal/adapter/postgres/users.go
  - internal/adapter/postgres/credentials.go
  - internal/adapter/postgres/sessions.go
  - internal/adapter/postgres/tokens.go
  - internal/adapter/postgres/*_test.go
done_when:
  - every repository port has a Postgres implementation
  - the existing port contract tests pass against it, unmodified
  - hydration uses Reconstitute* only — no validation on the read path
  - constraint violations map to the sentinel errors the ports declare
  - ADR 0008 hotspots use row locks or versioned retry, with a concurrency test
  - internal/domain and internal/app are unchanged by this task
  - make check + make vuln pass
---

# T34 — Postgres repository adapters

## Goal

Implement the repository ports against Postgres, behaviourally identical to the
in-memory store.

## The bar

The port contract tests already exist and already pass for `memory`. They should
pass for `postgres` **without modification**. If a test needs changing to
accommodate the new implementation, either the contract was under-specified or the
implementation is wrong — find out which before editing the test.

## Rules that are easy to break here

**Hydrate with `Reconstitute*`, never `New*`.** Storage holds trusted state; the
read path does not re-validate ([ADR 0003](../../adr/0003-new-vs-reconstitute-constructors.md)).
Using `New*` would re-stamp timestamps and reject rows that were legitimately
written under an older rule.

**Map errors to the declared sentinels.** A `23505` unique violation on the email
index becomes `port.ErrEmailTaken`, not a raw driver error — callers use
`errors.Is`, and `Register`'s enumeration safety depends on that mapping being
exact ([ADR 0012](../../adr/0012-repository-port-contract.md)).

**Serialise the hotspots.** [ADR 0008](../../adr/0008-aggregate-concurrency-contract.md)
names three, and each is a real race in SQL:

| Hotspot | Race if unguarded |
|---------|-------------------|
| Lockout counter | Two concurrent failed logins both read `failed_attempts = 4`, both write `5`. The account never locks — the exact scenario lockout exists to stop |
| Session touch/revoke | A touch that slides the idle window can resurrect a session revoked concurrently |
| Recovery-code consume | Two requests consume the same single-use code |

`SELECT ... FOR UPDATE` inside the transaction is the straightforward fix. An
optimistic version column also works. Pick one and be consistent; note that
`CLAUDE.md` explicitly rejected a global version field on aggregates, so a version
column here is a storage-level detail that must not leak into the domain.

**Test the concurrency, do not assert it.** A test that fires N goroutines at the
same user and asserts `failed_attempts == N` catches the lost update. Without it,
this task is unverified — `-race` finds Go data races, not SQL ones.

## Driver

`pgx` (native, better types, `pgxpool`) versus `database/sql` + `lib/pq`/`pgx` stdlib
mode. `pgx` is the usual choice and adds one dependency. Record it in
[T37](T37-adrs.md) — this is the first runtime dependency added since `x/text`,
so it deserves the paragraph.

Keep it confined to `internal/adapter/postgres`, the way `x/crypto` is confined to
`adapter/crypto` and `x/text` to `adapter/text`.

## Steps

1. `store.go` — pool construction, a `Store` exposing the four repositories,
   mirroring `memory.Store`'s shape so `cmd/server` wiring barely changes.
2. One file per repository.
3. Run the port contract tests against a real Postgres (Docker), tagged so they
   stay out of `make check` — same pattern as the Mailpit integration test.
4. Add the concurrency tests for the three hotspots.
