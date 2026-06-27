# Phase 01 — Driven Ports

**Layer:** `internal/port` · **Branch:** `phase-01-ports` · **Depends on:** nothing.

Declare the interfaces the application needs but does not implement. No I/O, no
crypto, no implementations — just contracts that import `internal/domain` only
(per [ADR 0001](../../adr/0001-strict-authn-only-ddd-layering.md)). Adapters in
Phase 02 satisfy them.

## Scope

| Task | File | What |
|------|------|------|
| [T01](T01-repo-ports.md) | `internal/port/repository.go` | 4 repository interfaces + uniqueness/serialization contracts |
| [T02](T02-password-hasher.md) | `internal/port/password_hasher.go` | produce-side hashing (pairs with existing `Authenticator`) |
| [T03](T03-token-generator.md) | `internal/port/token_generator.go` | mint opaque secret + its `TokenHash` |
| [T04](T04-clock.md) | `internal/port/clock.go` | `Now()` source for the app |
| [T05](T05-mailer.md) | `internal/port/mailer.go` | side-channel delivery of raw tokens |

## Exit criteria

- All 5 files compile; `internal/port` imports only stdlib + `internal/domain`.
- Interfaces are `context.Context`-first where they do I/O.
- Each task ships a `*_test.go` contract test: a `package port_test` fake satisfies
  the interface via a compile-time `var _ port.X = (*fake)(nil)` assertion (per the
  [Definition of done](../README.md#definition-of-done-every-task)).
- `make check` + `make vuln` pass.

## Current task

→ **T01** (everything in Phase 02/03 blocks on the repo ports). T02–T05 are
independent of T01 and of each other — parallelizable.
