---
id: T22
phase: 04-edge-wiring
title: main wiring + shutdown
status: todo
branch: phase-04-edge-wiring
layer: cmd/server
depends_on: [T20, T21]
touches:
  - cmd/server/main.go
  - cmd/server/main_test.go
done_when:
  - constructs adapters, injects use-cases, mounts router, serves
  - graceful shutdown on SIGINT/SIGTERM
  - tests implemented: factor wiring into a testable newServer()/build() so a test asserts the dependency graph constructs and the server starts + shuts down without error
  - make build produces a booting bin/server
  - make check passes (fmt-check, vet, staticcheck, go test -race)
  - make vuln passes
---

# T22 — main wiring + shutdown

## Goal

The composition root. The only place concrete adapters meet use-cases. Currently
`cmd/server/main.go` is `func main() {}`.

## Wiring order

```
cfg := config.Load()
log := slog.New(...)
clock := clock.System{}
store := memory.NewStore()                    // implements all 4 repo ports
hasher := crypto.NewBcrypt(cfg.BcryptCost)    // PasswordHasher + Authenticator
tokens := crypto.TokenGen{}
mail := mailer.NewLogMailer(log)
screen := screener.NoOp{}
policy := domain.DefaultPasswordPolicy()

// use-cases (Phase 03), each gets the ports it needs + cfg TTLs
register := app.NewRegister(store, store, store, hasher, tokens, mail, screen, clock, policy)
login := app.NewLogin(store, store, store, hasher, tokens, clock, cfg.IdleTTL, cfg.AbsTTL)
... verify, validate, logout, change, forgot, reset

mux := httpapi.NewRouter(httpapi.Deps{...}, cfg)
srv := &http.Server{Addr: cfg.ListenAddr, Handler: mux}
// serve in goroutine; wait on signal.NotifyContext; srv.Shutdown(ctx)
```

## Steps

1. Build every adapter, then every use-case, then the router.
2. `signal.NotifyContext(ctx, SIGINT, SIGTERM)`; on cancel call `srv.Shutdown`
   with a timeout.
3. Log the listen address; return non-zero on fatal startup error.
4. `make build` → run → curl the register endpoint to smoke-test.

## Notes

- Swapping in-memory→Postgres later changes only this file + a new adapter.
- Swapping the no-op screener for real HIBP later is also only here.
- Keep `main` flat and readable; the wiring is documentation of the dependency graph.
