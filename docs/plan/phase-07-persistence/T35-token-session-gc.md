---
id: T35
phase: 07-persistence
title: Expired token + session reclamation
status: todo
branch: phase-07-persistence
layer: internal/adapter/postgres, cmd/server
depends_on: [T34]
touches:
  - internal/adapter/postgres/gc.go
  - internal/adapter/postgres/gc_test.go
  - cmd/server/main.go
done_when:
  - consumed/expired verification tokens and dead sessions are deleted on a schedule
  - deletion is batched so it never holds a long lock on a hot table
  - the sweeper starts with the server and stops cleanly on shutdown
  - a retention window is configurable, with a safe default
  - tests prove live rows survive and only dead ones are removed
  - make check + make vuln pass
---

# T35 — Expired token + session reclamation

## Goal

Stop dead rows accumulating forever.

## Why it matters now and not before

Nothing has ever pruned `VerificationToken`s — not consumed ones, not expired
ones. In the in-memory store that is invisible: the process restarts and the map
is empty. In Postgres the rows are permanent, and two of them are on hot lookup
paths (`token_hash`, `session token_hash`). Every registration, every reset
request, and every login adds rows that are never removed.

## What to delete

| Table | Delete when |
|-------|-------------|
| `verification_tokens` | `consumed_at IS NOT NULL` or `expires_at < now - retention` |
| `sessions` | `revoked_at IS NOT NULL` or past absolute expiry, older than retention |

Keep a retention window rather than deleting the instant a row dies — a short grace
period (hours to days) keeps recent history available for debugging an "it said my
link was invalid" report. Make it configurable.

## Steps

1. `gc.go` — `DeleteExpiredTokens(ctx, olderThan)` / `DeleteDeadSessions(ctx, olderThan)`,
   each deleting in bounded batches (`DELETE ... WHERE id IN (SELECT ... LIMIT n)`)
   and looping. An unbounded `DELETE` on a large table locks it long enough to
   stall live authentication traffic.
2. A sweeper goroutine in `cmd/server`, on a ticker, using the injected `port.Clock`,
   cancelled by the existing shutdown context. It must not block graceful shutdown.
3. Log counts, never row contents — those rows contain token hashes.
4. Tests: seed live + dead rows, sweep, assert exactly the dead ones went, and that
   a row inside the retention window survives.

## Notes

- Alternative: a `pg_cron` job or an external cron. An in-process sweeper keeps the
  deployment to one artifact; with multiple replicas they will overlap harmlessly
  (deletes are idempotent) but will duplicate work. Note the choice in
  [T37](T37-adrs.md).
- A partial index on the "dead" predicate can keep the sweep cheap if these tables
  get large. Premature at current volume; worth a comment in the migration.
