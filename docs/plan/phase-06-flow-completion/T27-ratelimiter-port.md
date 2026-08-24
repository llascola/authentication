---
id: T27
phase: 06-flow-completion
title: RateLimiter port + in-memory adapter
status: todo
branch: phase-06-flow-completion
layer: internal/port, internal/adapter/ratelimit
depends_on: []
touches:
  - internal/port/rate_limiter.go
  - internal/port/rate_limiter_test.go
  - internal/adapter/ratelimit/memory.go
  - internal/adapter/ratelimit/memory_test.go
done_when:
  - port.RateLimiter declared in internal/port, stdlib+domain imports only
  - in-memory adapter implements it, safe for concurrent use, bounded memory
  - expired buckets are reclaimed (no unbounded map growth from unique keys)
  - contract test with a fake + compile-time var _ port.RateLimiter assertion
  - adapter tests cover allow, deny at limit, refill after window, concurrent use
  - tests run clean under -race; make check + make vuln pass
---

# T27 — RateLimiter port + in-memory adapter

## Goal

A driven port for "may this key act right now", plus the in-memory implementation
the single-process deployment needs.

## Port shape

```go
// Allow reports whether the action keyed by key may proceed now. When it may
// not, retryAfter is how long the caller should wait before retrying.
type RateLimiter interface {
    Allow(ctx context.Context, key string) (allowed bool, retryAfter time.Duration, err error)
}
```

Keep the key an opaque `string` — the edge decides what goes in it
([T28](T28-apply-rate-limits.md)), so the port stays ignorant of IPs, emails, and
routes. One limiter instance per policy (one for login, one for forgot, …) rather
than a policy argument on every call; that keeps configuration at the wiring site.

## Adapter

- Fixed-window counter or token bucket, keyed by string, behind a mutex.
- **Unbounded growth is the trap**: every distinct key allocates. An attacker
  varying the key mints entries forever. Reclaim expired buckets — a sweep on
  write, a periodic goroutine, or a small LRU. Whichever you pick, test it.
- Concurrency: this is a shared mutable map hit from every request. `-race` is
  the proof, and the [ADR 0008](../../adr/0008-aggregate-concurrency-contract.md)
  discipline applies — serialise the read-modify-write.

## Steps

1. `internal/port/rate_limiter.go` — interface + doc comment stating the contract.
2. Port contract test with a fake, plus `var _ port.RateLimiter = ...`.
3. `internal/adapter/ratelimit/memory.go` — constructor takes limit, window, and a
   `port.Clock` (the domain's clock-injection discipline, [ADR 0002](../../adr/0002-inject-clock-via-now-parameter.md),
   is why: a test must not sleep to prove a window refills).
4. Tests: under limit allows, at limit denies with a sane `retryAfter`, allows again
   after the window, reclaims expired keys, and survives `-race` under parallel load.

## Notes

- In-memory means **per-process**. Two replicas = two independent limits. Fine for
  the current single-process deployment; note it in [T32](T32-adrs.md) so the
  Redis-backed variant is a config swap later, not a redesign.
- Returning `err` on the interface looks unnecessary for the in-memory case, but a
  networked limiter (Redis) will need it. Decide deliberately in T32 — a port that
  needs widening later is worse than one error return now.
- Fail-open or fail-closed on limiter error is a security decision, not a detail.
  Record it in T32.
