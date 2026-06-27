---
id: T24
phase: 05-verify
title: ADRs for new port shapes
status: done
branch: phase-05-verify
layer: docs/adr
depends_on: [T01, T02, T03]
touches:
  - docs/adr/0012-*.md
  - docs/adr/README.md
done_when:
  - each newly-locked decision has an ADR following the template
  - docs/adr/README.md index updated
  - docs-only task (the README DoD carve-out): no Go code, so no test/govulncheck target
  - make check passes
---

# T24 — ADRs for new port shapes

## Goal

Record decisions this slice locked in, so future work treats them as settled
(supersede, don't edit — per the repo ADR convention).

## Candidate ADRs

- **Repository port contract** (T01): not-found-as-sentinel vs nil; uniqueness +
  token-invalidation living in the adapter; serialization left to the adapter.
- **Token generation recipe** (T03/T08): 32B crypto/rand → base64url raw → SHA-256
  hash; one generator for sessions + verification tokens.
- **App-layer NFC normalization** (T12): where normalization happens and why the
  domain stays normalization-free (ties to ADR 0006).
- **In-memory store as the slice's persistence** + the Postgres swap boundary, if
  worth fixing as a decision.

## Steps

1. Copy `docs/adr/0000-template.md` for each accepted decision, numbering from 0012.
2. Keep them short: context, decision, consequences. Link the originating task.
3. Update `docs/adr/README.md` index.
4. Only write an ADR for decisions that are actually *locked* and non-obvious —
   skip ceremony for trivial choices.

## Notes

- Do this AFTER the port shapes settle (hence Phase 05), so ADRs match reality.
- If a decision changed an existing ADR's assumptions, supersede it, don't edit.
