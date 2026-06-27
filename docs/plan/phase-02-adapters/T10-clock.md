---
id: T10
phase: 02-adapters
title: System clock
status: todo
branch: phase-02-adapters
layer: internal/adapter/clock
depends_on: [T04]
touches:
  - internal/adapter/clock/system.go
  - internal/adapter/clock/system_test.go
done_when:
  - implements port.Clock (compile-time assertion), returns time.Now().UTC()
  - tests implemented: Now() returns UTC location; two successive calls are non-decreasing
  - make check passes (fmt-check, vet, staticcheck, go test -race)
  - make vuln passes
---

# T10 — System clock

## Goal

Implement `port.Clock` (T04) with the wall clock in UTC.

## Design

```go
type System struct{}
func (System) Now() time.Time { return time.Now().UTC() }
```

## Steps

1. `internal/adapter/clock/system.go`, package `clock`.
2. Implement; compile-time `var _ port.Clock`.

## Notes

- UTC is deliberate: the domain stores whatever `now` it is handed; keep it UTC
  everywhere so timestamps compare cleanly.
- Tests use a fixed fake clock, not this; this is only wired in `main` (T22).
