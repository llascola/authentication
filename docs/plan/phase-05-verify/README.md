# Phase 05 — Verify + Record

**Layer:** tests, `docs/adr` · **Branch:** `phase-05-verify` · **Depends on:** Phase 04.

Prove the slice works end-to-end and record any decisions the build locked in.

## Scope

| Task | What |
|------|------|
| [T23](T23-integration-test.md) | Full-stack integration test on the wired in-memory server |
| [T24](T24-adrs.md) | ADRs for new port shapes (repos, hasher, token gen) if they lock decisions |

## Exit criteria

- T23 drives register → (read logged token) → verify → login → GET /me → logout →
  confirm session revoked, all green.
- Any new locked decision has an ADR that follows the existing template + index.
- `make check` + `make vuln` pass.

## Current task

→ **T23**. T24 follows once the port shapes have settled.
