---
id: T04
phase: 01-ports
title: Clock port
status: todo
branch: phase-01-ports
layer: internal/port
depends_on: []
touches:
  - internal/port/clock.go
  - internal/port/clock_test.go
done_when:
  - Clock interface compiles
  - tests implemented: a fixed-time fake satisfies Clock (compile-time `var _ port.Clock` assertion) and returns the injected instant
  - make check passes (fmt-check, vet, staticcheck, go test -race)
  - make vuln passes
---

# T04 — Clock port

## Goal

Give the app a single, fakeable source of `now`. The domain takes `now` as a
parameter and never calls `time.Now` ([ADR 0002](../../adr/0002-inject-clock-via-now-parameter.md));
the app needs something to *produce* it.

## Interface sketch

```go
type Clock interface {
    Now() time.Time   // adapter returns UTC
}
```

## Steps

1. New file `internal/port/clock.go`, package `port`.
2. Define `Clock`. Doc-comment: implementations return UTC; tests inject a fixed clock.

## Notes

- Trivial but real: lets every use-case test pin time without touching the wall clock.
- Adapter is T10 (`time.Now().UTC()`).
