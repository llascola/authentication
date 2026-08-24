# Phase 07 — Persistence

**Layer:** `internal/adapter/postgres`, `internal/config`, `cmd/server` ·
**Branch:** `phase-07-persistence` · **Depends on:** Phase 06.

Swap the in-memory store for Postgres. Until this lands, every restart wipes
users, credentials, sessions, and tokens — the flow is correct but the server
cannot actually be deployed.

## Why it is a clean swap

The slice was built for this. `cmd/server` is the only place adapters meet
use-cases, the repository contract is fixed by
[ADR 0012](../../adr/0012-repository-port-contract.md), and the port contract
tests already exist to hold a second implementation to the same behaviour. The
domain and application layers should not change at all — if they do, something
leaked, and that is worth stopping to look at.

## The part that is not mechanical

[ADR 0008](../../adr/0008-aggregate-concurrency-contract.md) says infrastructure
must serialise read-modify-write on a single aggregate. The in-memory store does
that with a mutex, which is trivially correct and teaches you nothing about what
Postgres needs. The named hotspots — session touch/revoke, lockout counter,
recovery-code consume — each need a row lock or an optimistic-version retry, and
getting that wrong produces races that no single-process test will catch.

## Scope

| Task | What |
|------|------|
| [T33](T33-schema-migrations.md) | Schema + migration tooling |
| [T34](T34-postgres-repositories.md) | Postgres implementations of the repository ports |
| [T35](T35-token-session-gc.md) | Expired token + session reclamation |
| [T36](T36-wiring-and-integration.md) | Config, wiring, integration test against real Postgres |
| [T37](T37-adrs.md) | ADRs for the persistence decisions |

## Exit criteria

- The full register → verify → login → logout flow survives a process restart.
- Every port contract test passes against the Postgres implementation.
- Concurrent writes to the lockout counter and session table are proven correct
  under `-race` and under real concurrency.
- Expired tokens and sessions do not accumulate forever.
- `make check` + `make vuln` pass; Postgres-dependent tests stay out of the
  blocking gate the same way the Mailpit integration test does.

## Current task

→ **T33**.
