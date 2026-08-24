---
id: T31
phase: 06-flow-completion
title: Real breach screener (HIBP k-anonymity)
status: todo
branch: phase-06-flow-completion
layer: internal/adapter/screener
depends_on: []
touches:
  - internal/adapter/screener/hibp.go
  - internal/adapter/screener/hibp_test.go
  - internal/config/config.go
  - cmd/server/main.go
done_when:
  - implements port.PasswordScreener against the HIBP range API
  - only the first 5 hex chars of the SHA-1 leave the process, never the password
  - has an explicit timeout and a recorded, tested fail-open/fail-closed behaviour
  - the no-op screener remains selectable by config for dev and CI
  - tests use a stubbed HTTP transport — no network in `make check`
  - make check + make vuln pass
---

# T31 — Real breach screener

## Goal

Replace the no-op stub with the breach check
[ADR 0011](../../adr/0011-nist-aligned-default-no-composition-rules.md) assumed:
NIST drops composition rules in exchange for screening against known-breached
passwords. Without the screen, the policy is weaker than the ADR intends —
`password1` currently passes.

## How k-anonymity works

1. `SHA-1(password)`, uppercase hex.
2. `GET https://api.pwnedpasswords.com/range/{first 5 chars}`.
3. Response is ~800 suffixes with counts. Match the remaining 35 chars **locally**.

The password never leaves the process, and the 5-char prefix maps to hundreds of
thousands of candidates, so the query does not identify it. Send `Add-Padding: true`
so the response length does not leak which prefix was queried.

SHA-1 here is a lookup index into a public dataset, not a security primitive —
this is not a hashing decision and does not touch
[ADR 0007](../../adr/0007-password-hashing-prehash-bcrypt-argon2id.md).

## The decision this task must make

**What happens when HIBP is unreachable?**

- *Fail-open* (allow the password): registration keeps working during an outage,
  but an attacker who can block the call downgrades you to no screening.
- *Fail-closed* (reject): no downgrade, but a third-party outage takes down
  registration and password changes entirely.

For a personal project, fail-open with a logged warning and a short timeout is the
defensible default — but it must be a recorded choice, not an accident of where
the `err` return went. Record it in [T32](T32-adrs.md).

## Steps

1. `internal/adapter/screener/hibp.go` — constructor takes an `*http.Client` so
   tests inject a stub transport and the timeout is explicit.
2. Timeout on the order of 2-3s; honour the request `context`.
3. Config: which screener to use (`noop` or `hibp`), so dev and CI stay offline by
   default and `make check` never touches the network.
4. Wire in `cmd/server`.
5. Tests with a stubbed transport: known-breached suffix rejects, unknown allows,
   timeout/5xx follows the recorded fail policy, and the request URL contains only
   the 5-char prefix. That last assertion is the one that catches a refactor
   accidentally sending the whole hash.

## Notes

- Stdlib `net/http` and `crypto/sha1` only — no new module dependency, so the
  minimal-dependency rule in `CLAUDE.md` holds.
- Consider caching negative results briefly. Optional; a per-registration HTTP call
  is acceptable at this volume.
- HIBP's range endpoint needs no API key. The breached-*account* API does — not used here.
