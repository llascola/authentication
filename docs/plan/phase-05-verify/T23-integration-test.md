---
id: T23
phase: 05-verify
title: Integration test
status: done
branch: phase-05-verify
layer: internal/adapter/http (or test/)
depends_on: [T22]
touches:
  - internal/adapter/http/integration_test.go
done_when:
  - drives register -> read logged token -> verify -> login -> GET /me -> logout
  - asserts session works before logout and is rejected after
  - asserts unverified account cannot log in
  - runs under `go test -race`; make check + make vuln pass
---

# T23 — Integration test

## Goal

Prove the whole password slice works end-to-end against the wired in-memory stack.

## Scenario

```
1. POST /auth/register {email, password}        -> 200/201
2. capture raw token from the LogMailer output  (inject a capturing logger)
3. attempt POST /auth/login BEFORE verify        -> 401 (verify required)
4. POST /auth/verify-email {token}              -> 200, user now active
5. POST /auth/login {email, password}           -> 200 + Set-Cookie
6. GET /auth/me with cookie                      -> 200, returns the user id
7. POST /auth/logout with cookie                 -> 200, cookie cleared
8. GET /auth/me with old cookie                  -> 401 (session revoked)
```

## Steps

1. Build the full stack in-process (reuse T22 wiring or a test constructor) with a
   `LogMailer` writing to a captured buffer/handler so the test can read the token.
2. Use `httptest.NewServer` + an `http.Client` with a cookie jar.
3. Assert each status + the before/after session behaviour.
4. Add the negative: wrong password → 401, counter increments (optional: trip lockout).
5. Run with `-race` (it is the slice's concurrency proof too).

## Notes

- Capturing the token from logs is the deliberate stand-in for "user reads email."
- Keep it black-box over HTTP — exercises router + middleware + use-cases + store
  together, the real integration surface.
- If T17-T19 landed, add change/forgot/reset legs; otherwise core flow is enough.
