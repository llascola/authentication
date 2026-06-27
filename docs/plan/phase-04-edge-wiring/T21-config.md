---
id: T21
phase: 04-edge-wiring
title: Config loader
status: todo
branch: phase-04-edge-wiring
layer: cmd/server
depends_on: []
touches:
  - internal/config/config.go
  - internal/config/config_test.go
done_when:
  - loads listen addr, idle/abs session TTL, bcrypt cost from env with defaults
  - invalid values rejected with a clear error
  - tests implemented: cover defaults + overrides + invalid (duration/cost) inputs
  - make check passes (fmt-check, vet, staticcheck, go test -race)
  - make vuln passes
---

# T21 — Config loader

## Goal

Env-driven configuration with sane defaults. No external config lib.

## Fields (slice scope)

| Env | Default | Used by |
|-----|---------|---------|
| `AUTH_LISTEN_ADDR` | `:8080` | T22 server |
| `AUTH_SESSION_IDLE_TTL` | `30m` | T14 login |
| `AUTH_SESSION_ABS_TTL` | `24h` | T14 login |
| `AUTH_BCRYPT_COST` | `10` (DefaultCost) | T07 hasher |
| `AUTH_COOKIE_SECURE` | `true` | T20 cookie (allow false for local http) |

## Steps

1. `internal/config/config.go`, package `config`. A `Config` struct + `Load() (Config, error)`.
2. Parse durations with `time.ParseDuration`; validate `idle <= abs` (domain also
   enforces, but fail early with a clear message).
3. Validate bcrypt cost within `bcrypt.MinCost..MaxCost`.
4. Tests: defaults applied; overrides parsed; invalid duration / cost rejected.

## Notes

- `AUTH_COOKIE_SECURE=false` only for local `http://` dev; default true.
- Keep it boring stdlib (`os.Getenv` + `strconv`/`time`). A flag layer can wrap later.
