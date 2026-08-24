---
id: T33
phase: 07-persistence
title: Postgres schema + migrations
status: todo
branch: phase-07-persistence
layer: internal/adapter/postgres
depends_on: []
touches:
  - internal/adapter/postgres/migrations/
  - Makefile
  - docs/adr/
done_when:
  - schema covers users, credentials, sessions, verification_tokens
  - cross-aggregate uniqueness from ADR 0009 is enforced by DB constraints
  - token and session hashes are indexed for the lookup paths the app uses
  - migrations are versioned, forward-only, and runnable from a make target
  - a documented way to run them in dev, CI, and production
  - make check passes
---

# T33 — Postgres schema + migrations

## Goal

The tables, constraints, and indexes the repository ports need, plus a way to
apply them.

## Schema notes

Derive columns from the aggregates' `Reconstitute*` signatures — those are the
exact fields storage must round-trip
([ADR 0003](../../adr/0003-new-vs-reconstitute-constructors.md)). If a field is
not in `Reconstitute*`, it does not belong in the table.

- **users** — id (uuid pk), email (citext or lower(email) unique index), status,
  email_verified, failed_attempts, locked_until, timestamps.
- **credentials** — id, user_id fk, kind discriminator, hash bytes, timestamps.
  `Credential` is a sealed interface with typed implementations
  ([ADR 0004](../../adr/0004-typed-per-kind-credentials.md)); do **not** flatten
  it into a JSON blob to make storage easier — that reverses a locked decision.
- **sessions** — id, user_id fk, token_hash (unique, indexed — it is the lookup
  key), issued_at, last_seen_at, idle/absolute expiry, revoked_at.
- **verification_tokens** — id, user_id fk, purpose, token_hash (unique, indexed),
  expires_at, consumed_at.

**Constraints, not application checks.** [ADR 0009](../../adr/0009-cross-aggregate-uniqueness-constraints.md)
puts uniqueness at the repository layer; in Postgres that means a unique index, so
the guarantee holds under concurrency instead of losing a race between a `SELECT`
and an `INSERT`. Map the resulting constraint violation back to `port.ErrEmailTaken`
in [T34](T34-postgres-repositories.md).

Store only hashes. No raw token or password ever reaches a column
([ADR 0013](../../adr/0013-opaque-token-generation-and-rehash.md)).

Timestamps as `timestamptz`, always UTC. The domain takes an injected `now`
([ADR 0002](../../adr/0002-inject-clock-via-now-parameter.md)) — do not let a
column default to `now()` and silently become a second, unmockable clock.

## Migration tooling — decide first

Options, roughly in increasing weight: plain `.sql` files applied by a tiny
stdlib runner using `embed`; `golang-migrate`; `goose`; `atlas`. The
minimal-dependency rule in `CLAUDE.md` favours the first, and an
`embed.FS` + a `schema_migrations` table is genuinely small. Record the choice in
[T37](T37-adrs.md).

Forward-only. Down-migrations are rarely correct under real data and invite
someone to run one in production.

## Steps

1. Pick the tooling, record it.
2. Write the initial migration.
3. `make migrate` (and a `make db-up` for a local Postgres via Docker, mirroring
   `scripts/mailpit-integration.sh`).
4. Document how migrations run on deploy — a startup step, or a separate command.
   Startup migration is convenient and dangerous with multiple replicas; if you
   choose it, say why in the ADR.
