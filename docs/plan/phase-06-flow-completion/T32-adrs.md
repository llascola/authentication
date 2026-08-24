---
id: T32
phase: 06-flow-completion
title: ADRs for phase 06 decisions
status: done
branch: phase-06-flow-completion
layer: docs/adr
depends_on: [T25, T27, T29, T30, T31]
touches:
  - docs/adr/
  - docs/adr/README.md
done_when:
  - each decision below has an ADR following the 0000 template
  - the ADR that changes ADR 0015's revocation rule says "supersedes", not an edit
  - docs/adr/README.md index lists every new ADR
  - CLAUDE.md's decision list mentions the new ADRs
  - make check passes
---

# T32 — ADRs for phase 06 decisions

## Goal

Record what this phase locked, so the next person (or the next context) does not
re-litigate it from the code.

Docs-only task, so the usual test/vuln gates have nothing to cover — `make check`
still applies. This is the same carve-out T24 used.

## Decisions to record

| Decision | From | The part that must be written down |
|----------|------|-----------------------------------|
| Resend-verification policy | [T25](T25-resend-verification.md) | Enumeration-safe always-success; which account states get a token; per-user cooldown vs edge-only limiting |
| Rate-limit shape and policy | [T27](T27-ratelimiter-port.md), [T28](T28-apply-rate-limits.md) | Port shape and why the key is an opaque string; per-IP **and** per-email keying; chosen limits/windows; in-memory means per-process; fail-open vs fail-closed on limiter error; why `RemoteAddr` only |
| CSRF scheme | [T29](T29-csrf.md) | Double-submit bound to the session; which routes; why login/register are exempt; why the CSRF cookie is not HttpOnly |
| Session preservation on password change | [T30](T30-revoke-all-except.md) | **Supersedes** the revocation clause of [ADR 0015](../../adr/0015-http-edge-security-posture.md). Why the trade moved, and why ResetPassword stays all-revoking |
| Breach-screen fail policy | [T31](T31-hibp-screener.md) | k-anonymity mechanism; fail-open vs fail-closed and why; timeout; that SHA-1 is an index, not a hashing decision |

## Steps

1. One ADR per row — do not bundle unrelated decisions into one document.
2. Copy `docs/adr/0000-template.md`; keep Status/Date/Context/Decision/Consequences.
3. Number sequentially from the current highest (0016 at time of writing).
4. Update `docs/adr/README.md`.
5. Update the "Decisions" section of `CLAUDE.md` with the new entries.

## Notes

- Per `CLAUDE.md`: to reverse a locked decision, add an ADR that supersedes it —
  never edit the old one. Only the T30 ADR does that here.
- Write the ADR when the decision is made, not after the code is merged. A
  rationale reconstructed a week later is a rationalisation.
