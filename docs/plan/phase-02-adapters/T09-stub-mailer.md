---
id: T09
phase: 02-adapters
title: Stub mailer
status: todo
branch: phase-02-adapters
layer: internal/adapter/mailer
depends_on: [T05]
touches:
  - internal/adapter/mailer/log.go
  - internal/adapter/mailer/log_test.go
done_when:
  - implements port.Mailer (compile-time assertion)
  - logs recipient + raw token to a provided logger/io.Writer
  - tests implemented: capture the logger output, assert recipient + raw token present for both verify and reset
  - make check passes (fmt-check, vet, staticcheck, go test -race)
  - make vuln passes
---

# T09 — Stub mailer

## Goal

Implement `port.Mailer` (T05) by logging the raw token. Lets the integration test
(T23) read the token a real user would receive by email.

## Context

- Port: [T05](../phase-01-ports/T05-mailer.md).
- Slice decision: stub mailer, verify required.

## Design

```go
type LogMailer struct{ log *slog.Logger }

func (m LogMailer) SendEmailVerification(ctx, to domain.Email, rawToken string) error {
    m.log.Info("email verification", "to", to.String(), "token", rawToken)
    return nil
}
// SendPasswordReset similar
```

## Steps

1. `internal/adapter/mailer/log.go`, package `mailer`.
2. Implement both methods; compile-time `var _ port.Mailer`.
3. Accept an injected `*slog.Logger` (or `io.Writer`) so T23 can capture output.

## Notes

- **Dev-only**: real mailer must never log the token. Put a loud comment.
- Keep output machine-parseable (structured fields) so T23 can extract the token.
