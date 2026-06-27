# Phase 04 — Edge + Wiring

**Layer:** `internal/adapter/http`, `cmd/server` · **Branch:** `phase-04-edge-wiring`
· **Depends on:** Phase 03.

The driving edge (HTTP) and the composition root. This is where the process
becomes a runnable server.

## Scope

| Task | Where | What |
|------|-------|------|
| [T20](T20-http.md) | `internal/adapter/http` | handlers, router, cookie, error→status map |
| [T21](T21-config.md) | `cmd/server` (or `internal/config`) | env-driven config (addr, TTLs, policy) |
| [T22](T22-main.md) | `cmd/server/main.go` | construct adapters → inject use-cases → serve → graceful shutdown |

## Exit criteria

- `make build` produces `bin/server`; it boots and serves.
- Error→status map preserves enumeration safety (no "user not found" leakage).
- Session cookie is `HttpOnly`, `Secure`, `SameSite`.
- `make check` + `make vuln` pass.

## Current task

→ **T20** then **T21** (parallel), then **T22** ties them together.
