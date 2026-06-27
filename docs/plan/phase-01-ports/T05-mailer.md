---
id: T05
phase: 01-ports
title: Mailer port
status: done
branch: phase-01-ports
layer: internal/port
depends_on: []
touches:
  - internal/port/mailer.go
  - internal/port/mailer_test.go
done_when:
  - Mailer interface compiles
  - tests implemented: a recording test stub satisfies Mailer (compile-time `var _ port.Mailer` assertion)
  - make check passes (fmt-check, vet, staticcheck, go test -race)
  - make vuln passes
---

# T05 — Mailer port

## Goal

Deliver a raw verification/reset secret over a side channel (email). For the
slice the adapter (T09) just logs it; the port stays delivery-agnostic.

## Interface sketch

```go
type Mailer interface {
    SendEmailVerification(ctx context.Context, to domain.Email, rawToken string) error
    SendPasswordReset(ctx context.Context, to domain.Email, rawToken string) error
}
```

## Steps

1. New file `internal/port/mailer.go`, package `port`.
2. Define `Mailer` with the two methods the slice needs (email-verify, reset).
3. Doc-comment: `rawToken` is secret; real impls must not log it (the stub does,
   for local dev only — call that out).

## Notes

- Magic-link / phone-verify methods exist in the domain but are out of slice scope.
- Keep method-per-purpose (clear call sites) rather than a generic `Send(template,...)`.
