---
id: T26
phase: 06-flow-completion
title: Resend-verification endpoint
status: todo
branch: phase-06-flow-completion
layer: internal/adapter/http
depends_on: [T25]
touches:
  - internal/adapter/http/handlers.go
  - internal/adapter/http/router.go
  - internal/adapter/http/handlers_test.go
  - cmd/server/main.go
done_when:
  - POST /auth/verify-email/resend accepts {email} and always returns the same 2xx
  - response body and status are identical for known, unknown, and verified addresses
  - handler is thin: decode, call one use-case, encode — no branching on account state
  - wired through httpapi.Deps and cmd/server
  - tests assert the three cases are indistinguishable at the HTTP surface
  - make check + make vuln pass
---

# T26 — Resend-verification endpoint

## Goal

Expose [T25](T25-resend-verification.md) over HTTP, matching the existing edge
conventions exactly.

## Shape

```
POST /auth/verify-email/resend
{"email": "user@example.com"}
-> 202 Accepted, fixed body, always
```

Public route (the user cannot be logged in — that is the whole point), so it sits
alongside `/auth/password/forgot` rather than behind `requireAuth`.

## Steps

1. Add `ResendVerification` to `httpapi.Deps`.
2. Handler in `handlers.go`, modelled on `forgotPassword` — same decode helper,
   same body-size limit, same fixed response.
3. Route in `router.go`.
4. Wire the service in `cmd/server/main.go`'s `newServer`.
5. Tests in `handlers_test.go`: known / unknown / already-verified all produce a
   byte-identical response.

## Notes

- Status choice: `202 Accepted` reads more honestly than `200` for "we may or may
  not have sent something", but match whatever `/auth/password/forgot` already
  returns — consistency at the edge beats semantic precision here. Check first.
- No new error mappings. Any failure the use-case returns is already covered by
  the central map in `errors.go`; do not add a status for "no such account"
  ([ADR 0015](../../adr/0015-http-edge-security-posture.md)).
- Ship [T28](T28-apply-rate-limits.md) before this route is exposed publicly.
