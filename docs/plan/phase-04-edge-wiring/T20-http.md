---
id: T20
phase: 04-edge-wiring
title: HTTP handlers + router
status: todo
branch: phase-04-edge-wiring
layer: internal/adapter/http
depends_on: [T12, T13, T14, T15, T16, T17, T18, T19]
touches:
  - internal/adapter/http/handlers.go
  - internal/adapter/http/router.go
  - internal/adapter/http/middleware.go
  - internal/adapter/http/handlers_test.go
done_when:
  - routes for register/verify/login/logout/me/change/forgot/reset
  - session token in HttpOnly+Secure+SameSite cookie; cleared on logout
  - domain/app errors map to status codes without leaking enumeration
  - auth middleware uses ValidateSession (T15)
  - handler tests with httptest pass
  - make check + make vuln pass
---

# T20 — HTTP handlers + router

## Goal

The driving HTTP edge over the Phase 03 use-cases. Stdlib `net/http`.

## Routes

| Method | Path | Use-case | Auth |
|--------|------|----------|------|
| POST | `/auth/register` | T12 | no |
| POST | `/auth/verify-email` | T13 | no |
| POST | `/auth/login` | T14 | no (sets cookie) |
| POST | `/auth/logout` | T16 | cookie |
| GET  | `/auth/me` | T15 | cookie |
| POST | `/auth/password/change` | T17 | cookie |
| POST | `/auth/password/forgot` | T18 | no |
| POST | `/auth/password/reset` | T19 | no |

## Steps

1. `internal/adapter/http/`, package `http` (or `httpapi` to avoid stdlib clash).
2. Use `http.ServeMux` (Go 1.22+ method+pattern routing) — no router dep.
3. JSON decode/encode helpers; reject oversized bodies (`http.MaxBytesReader`).
4. **Cookie**: on login set `Set-Cookie` with `HttpOnly`, `Secure`, `SameSite=Lax`,
   `Path=/`, `MaxAge` = absolute TTL; on logout clear it (`MaxAge=-1`).
5. **Auth middleware**: read cookie → `ValidateSession` (T15) → inject UserID into
   request context → 401 on failure.
6. **Error map** (central): `ErrAuthFailed`/`ErrNotAuthenticated` → 401; policy
   violations → 400; everything enumeration-sensitive → identical generic responses.
   Register dup-email and login failures must be indistinguishable from success/
   generic failure respectively.
7. Build `DeviceInfo` from `RemoteAddr` + `User-Agent`; pass to login.
8. Tests with `net/http/httptest`: full cookie round-trip, 401s, validation 400s.

## Notes

- Extract the client IP carefully (RemoteAddr host:port split); no proxy trust for
  the slice.
- Keep handlers thin: decode → call use-case → encode. No domain logic here.
- Map is the one place status codes live — keep enumeration safety auditable.
