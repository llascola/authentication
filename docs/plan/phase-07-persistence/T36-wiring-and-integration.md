---
id: T36
phase: 07-persistence
title: Wiring, config, and integration test against real Postgres
status: todo
branch: phase-07-persistence
layer: cmd/server, internal/config
depends_on: [T34, T35]
touches:
  - internal/config/config.go
  - internal/config/config_test.go
  - cmd/server/main.go
  - cmd/server/main_test.go
  - internal/adapter/http/integration_test.go
  - scripts/
  - Makefile
done_when:
  - store selection is config-driven; empty DSN keeps the in-memory store for dev
  - pool sizing, connect timeout, and statement timeout are configured explicitly
  - startup fails loudly on an unreachable database, with no credentials in the log
  - the full HTTP flow passes against real Postgres, including across a restart
  - Postgres-dependent tests stay out of the blocking make check gate
  - make check + make vuln pass
---

# T36 — Wiring, config, and integration

## Goal

Make Postgres the real backing store, and prove the flow survives a restart —
the property this whole phase exists for.

## Config

Follow the mailer precedent in `internal/config`: an empty `AUTH_DATABASE_URL`
selects the in-memory store (dev, CI, and the existing tests keep working), and a
set one selects Postgres with the rest of the settings validated eagerly. A
half-configured database should fail at startup, not at first query.

Set explicitly rather than inheriting driver defaults: max pool connections,
connection lifetime, connect timeout, and a statement timeout. An unbounded pool
against a small Postgres is how a login spike becomes an outage.

**The DSN contains a password.** It must never be logged, never appear in an error
string returned to a caller, and never land in a `%+v` dump of `Config`. Give
`Config` a redacting `LogValue()`/`String()` and cover it with a test that asserts
the secret does not appear in the output — the same exposure applies to
`AUTH_SMTP_PASS`, so do both at once.

## The restart test

This is the acceptance criterion for the phase:

```
1. register + verify + login against a Postgres-backed server  -> cookie
2. shut the server down, start a new one on the same database
3. GET /auth/me with the old cookie                            -> 200
```

The existing in-memory integration test cannot express that, which is precisely
the gap. Keep both: the in-memory one stays in `make check`, the Postgres one is
build-tagged and runs from a script that provisions a throwaway database in
Docker — same pattern as `scripts/mailpit-integration.sh`.

## Steps

1. Config fields + validation + redaction test.
2. `buildStore(cfg)` in `cmd/server`, mirroring `buildMailer`.
3. `newServer` already returns an error — extend it for store construction.
4. `scripts/postgres-integration.sh` + a `make test-integration-db` target.
5. The restart test above.
6. Update `CLAUDE.md`'s architecture notes: the store is no longer "in-memory only",
   and `x/crypto` / `x/text` are no longer the only confined dependencies if `pgx`
   landed in [T34](T34-postgres-repositories.md).

## Notes

- Keep the in-memory store. It is what makes `make check` fast and hermetic, and
  the port contract tests need two implementations to stay honest.
- Health check: `/healthz` that pings the pool is worth adding here rather than as
  its own task, now that there is something for it to report on.
