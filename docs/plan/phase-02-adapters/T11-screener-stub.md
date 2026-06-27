---
id: T11
phase: 02-adapters
title: Screener stub (no-op)
status: done
branch: phase-02-adapters
layer: internal/adapter/screener
depends_on: []
touches:
  - internal/adapter/screener/noop.go
  - internal/adapter/screener/noop_test.go
done_when:
  - implements port.PasswordScreener (compile-time assertion), always returns nil
  - tests implemented: Screen returns nil for a normal, an empty, and a known-breached sample input
  - make check passes (fmt-check, vet, staticcheck, go test -race)
  - make vuln passes
---

# T11 — Screener stub (no-op)

## Goal

Satisfy the existing `port.PasswordScreener` so the Register/Change/Reset
use-cases can call it without a real breach corpus. Real HIBP/dump is post-slice.

## Context

- Port already exists: `internal/port/password_screener.go`.
- [ADR 0011](../../adr/0011-nist-aligned-default-no-composition-rules.md) — breach
  screening is the NIST control replacing composition rules. The slice keeps the
  call site; the impl is a placeholder.

## Design

```go
type NoOp struct{}
func (NoOp) Screen(ctx context.Context, plaintext string) error { return nil }
```

## Steps

1. `internal/adapter/screener/noop.go`, package `screener`.
2. Implement; compile-time `var _ port.PasswordScreener`.

## Notes

- **Loud comment**: this accepts breached passwords — replace before any real use.
- Keeping the call wired now means swapping in a real screener later touches only
  `main` (T22), not the use-cases.
