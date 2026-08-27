# 0022. Process-level edge hardening: deadlines, response headers, liveness

- Status: Accepted
- Date: 2026-08-26
- Extends: [0015](0015-http-edge-security-posture.md), which covered the request
  and response *semantics* of the edge but not the process serving them
- Relates to: [0021](0021-rate-limiting-shape-and-policy.md) — a deadline bounds
  what a rate limit cannot

## Context

[ADR 0015](0015-http-edge-security-posture.md) settled the security posture of
the HTTP edge at the level of individual requests: cookie attributes,
enumeration-safe statuses, timing equalisation, session revocation. Everything
it decided is about what a handler *says*.

Three gaps sit one level below that, in the `http.Server` and the response
plumbing rather than in any handler. None of them was a decision anyone made and
recorded; all three are simply what you get from the zero value.

**Deadlines.** Only `ReadHeaderTimeout` was set. Go treats a zero timeout as *no
timeout*, so `ReadTimeout`, `WriteTimeout`, and `IdleTimeout` were all absent.
`http.MaxBytesReader` bounds how many bytes a request may carry, not how slowly
they may arrive: a client dribbling a 64 KiB body one byte at a time satisfies
every size limit and holds a connection and a goroutine indefinitely. This is
the classic slow-loris, aimed at the body rather than the headers.

It interacts badly with [ADR 0021](0021-rate-limiting-shape-and-policy.md). The
per-email limiter derives its key by reading the request body, so it runs
*before* the handler and stalls inside the middleware. A rate limit counts
completed attempts; it has nothing to say about a request that never completes.
Only a deadline bounds that.

**Response headers.** Responses carried `Content-Type` and nothing else. A `200`
with no cache directives is heuristically cacheable under RFC 9111 §4.2.2, and
`GET /auth/me` answers `200` with the caller's own user id. A shared cache keys
on the URL, not on the session cookie that distinguishes one caller from the
next, so a proxy or CDN in front of this server can serve one user's identity to
another — with no attacker in the picture at all.

**Limiter memory.** The in-process limiter of
[ADR 0021](0021-rate-limiting-shape-and-policy.md) mints a bucket per key and
reclaimed them at most once per policy window. Three of the four wired limiters
use a one-hour window, so an entry falling idle just after a sweep survived
nearly two hours, and nothing capped the map at all. Keys are cheap to vary — a
fresh source address out of an IPv6 `/64`, or a subaddressed email, per request
— so the throttle's own bookkeeping was an unbounded allocation an attacker
controlled.

**Liveness.** The router mounted nine routes, all under `/auth/`. A load
balancer had nothing to probe but the TCP port, which stays open while the
process is wedged, and a rolling deploy had no signal to gate on.

## Decision

We will set every `http.Server` deadline, and derive the write budget from
config rather than fixing it:

```go
ReadHeaderTimeout: 10s
ReadTimeout:       15s
IdleTimeout:       60s
WriteTimeout:      max(15s, AUTH_SCREENER_TIMEOUT + 10s)
```

`WriteTimeout` is derived because the slowest handler's duration is itself
configurable — the register and password-reset paths block on the breach
screener ([ADR 0019](0019-breach-screening-hibp-k-anonymity-fail-open.md))
before they write anything. A hard-coded budget would silently begin truncating
those responses the moment an operator raised the screener timeout past it.

We will set `Cache-Control: no-store` and `X-Content-Type-Options: nosniff` on
every response, from one helper called by the two functions that finish a
handler (`writeJSON` and `writeNoContent`). `no-store` rather than a narrower
directive plus `Vary: Cookie`: every response this server produces is
per-session by definition and none is worth caching, so the blunt answer is the
correct one and leaves nothing to reason about per route.

We will decouple limiter reclamation from the policy window (sweep at most
every `min(window, 1m)`) and cap the bucket map, evicting under pressure. The
eviction rule is the security-bearing part: **a bucket currently holding less
than one token is never evicted.** Evicting a live bucket returns quota — the
key's next request finds no entry and starts at full capacity — so dropping a
throttled key would let an attacker clear their own throttle by flooding the map
with junk keys, turning memory pressure into a limiter bypass. What stays
evictable is exactly what a key-rotation flood creates: keys used once, sitting
near capacity, that a window's age would have freed anyway.

We will serve `GET /healthz` as a liveness probe that checks nothing — no
session, no CSRF token, no rate limit, no store access, empty body, outside
`/auth/`. A health endpoint that pings its dependencies turns one slow
dependency into a synchronised restart of every replica, which is a worse
outage than the one it detects. Readiness, if it is ever needed, will be a
second endpoint with its own semantics rather than a widening of this one.

## Consequences

- A slow-loris now costs the attacker a reconnect every 15 seconds instead of
  nothing. The 64 KiB size cap and the deadline bound different axes of the same
  request; both are needed.
- `WriteTimeout` must stay above the slowest handler. It is derived from
  `AUTH_SCREENER_TIMEOUT` today; any future handler that can block longer than
  the write budget — a slow external call on the login path, say — has to be
  added to that derivation, or it will be cut off mid-response. This is the one
  piece of ongoing maintenance the decision creates.
- The deadlines are constants, not configuration. Auth payloads are small and
  fast, so there is no deployment that needs a different number badly enough to
  justify four more environment variables. A deployment that proves otherwise
  should promote them then, not pre-emptively.
- `no-store` on every response forecloses any future caching of a `GET` at this
  edge. Nothing here is cacheable, so nothing is lost; a future route that
  genuinely wants a cache directive will have to opt out of the helper
  deliberately, which is the right amount of friction.
- The limiter's memory is now bounded by roughly the keys seen within one
  window, plus however many of those are currently throttled. That residual is
  deliberate — enforcement outranks the ceiling — and it is not cheap to reach,
  since draining a key costs the attacker a full limit's worth of requests per
  entry. If every bucket is throttled, the map stays over its cap by design.
- The eviction ceiling is a constant, not configuration: this adapter is the
  single-process stand-in that Phase 07 replaces with a shared backend, and a
  limit nobody can tune is one nobody can set to zero by accident.
- `/healthz` is an unauthenticated route that confirms the server exists. That
  is not a leak — anything that can connect already knows — but it does mean the
  route must stay dumb. Adding a store check, a version string, or a dependency
  report to it would turn a probe into an information source and an outage
  amplifier at the same time.
- The probe is deliberately not under `/auth/`, so it cannot be caught by a
  future blanket rule applied to the auth prefix.
