# Phase 02 — Adapters

**Layer:** `internal/adapter` · **Branch:** `phase-02-adapters` · **Depends on:** Phase 01.

Implement the Phase 01 ports with concrete infrastructure. Each adapter is an
independent task once its port exists. This is where crypto, storage, and the
clock live — the domain never touches any of it.

## Scope

| Task | Package | Implements |
|------|---------|-----------|
| [T06](T06-memory-store.md) | `internal/adapter/memory` | all 4 repository ports (T01) |
| [T07](T07-bcrypt.md) | `internal/adapter/crypto` | `PasswordHasher` (T02) + `Authenticator` |
| [T08](T08-token-gen.md) | `internal/adapter/crypto` | `TokenGenerator` (T03) |
| [T09](T09-stub-mailer.md) | `internal/adapter/mailer` | `Mailer` (T05) — logs token |
| [T10](T10-clock.md) | `internal/adapter/clock` | `Clock` (T04) |
| [T11](T11-screener-stub.md) | `internal/adapter/screener` | `PasswordScreener` — no-op |

## Exit criteria

- Each adapter satisfies its port (compile-time `var _ port.X = (*Impl)(nil)`).
- T06 enforces unique email + token invalidation + RMW serialization
  ([ADR 0008](../../adr/0008-aggregate-concurrency-contract.md),
  [ADR 0009](../../adr/0009-cross-aggregate-uniqueness-constraints.md)) and has tests.
- `golang.org/x/crypto` added to `go.mod` (T07).
- `make check` + `make vuln` pass.

## Current task

→ **T06** (the use-cases in Phase 03 need a store). T07/T08/T09/T10/T11 parallel.
