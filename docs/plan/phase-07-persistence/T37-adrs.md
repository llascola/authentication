---
id: T37
phase: 07-persistence
title: ADRs for persistence decisions
status: todo
branch: phase-07-persistence
layer: docs/adr
depends_on: [T33, T34, T35]
touches:
  - docs/adr/
  - docs/adr/README.md
done_when:
  - driver, migration tooling, concurrency strategy, and GC placement each recorded
  - docs/adr/README.md index lists every new ADR
  - CLAUDE.md's decision list and dependency notes updated
  - make check passes
---

# T37 — ADRs for persistence decisions

## Goal

Record the persistence choices while the reasons are still fresh.

Docs-only, same carve-out as T24 and T32: nothing for the test and vuln gates to
cover, `make check` still applies.

## Decisions to record

| Decision | From | The part that must be written down |
|----------|------|-----------------------------------|
| Driver | [T34](T34-postgres-repositories.md) | `pgx` vs `database/sql`; why the first new runtime dependency since `x/text` is justified; that it stays confined to `adapter/postgres` |
| Migration tooling | [T33](T33-schema-migrations.md) | Which tool and why; forward-only; where migrations run on deploy and the multi-replica risk if they run at startup |
| Concurrency strategy | [T34](T34-postgres-repositories.md) | Row locks vs optimistic version, per hotspot; how this satisfies [ADR 0008](../../adr/0008-aggregate-concurrency-contract.md) without leaking a version field into the domain |
| Uniqueness enforcement | [T33](T33-schema-migrations.md) | DB unique indexes as the mechanism behind [ADR 0009](../../adr/0009-cross-aggregate-uniqueness-constraints.md), and the constraint-violation → sentinel mapping |
| GC placement + retention | [T35](T35-token-session-gc.md) | In-process sweeper vs external cron; retention window; batching to avoid long locks |

## Steps

1. One ADR per row; copy `docs/adr/0000-template.md`.
2. Number sequentially from the highest existing.
3. Update `docs/adr/README.md` and `CLAUDE.md`.

## Notes

- None of these supersede an existing ADR — they implement 0008, 0009, and 0012
  rather than reversing them. If implementing one of those forces a change to it,
  that is a supersede and needs saying so explicitly.
- `CLAUDE.md` currently describes the runtime dependency set precisely. If `pgx`
  landed, that paragraph is now wrong and must be updated in this task.
