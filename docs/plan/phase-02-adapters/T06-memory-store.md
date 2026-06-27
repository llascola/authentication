---
id: T06
phase: 02-adapters
title: In-memory store
status: done
branch: phase-02-adapters
layer: internal/adapter/memory
depends_on: [T01]
touches:
  - internal/adapter/memory/store.go
  - internal/adapter/memory/store_test.go
done_when:
  - implements all 4 repository ports (compile-time assertions)
  - unique email enforced; duplicate returns port.ErrEmailTaken
  - VerificationToken.Create invalidates prior unconsumed (user,purpose)
  - read-modify-write serialized under a mutex (ADR 0008)
  - tests cover uniqueness, not-found, token invalidation
  - make check + make vuln pass
---

# T06 — In-memory store

## Goal

Map-backed implementation of the 4 repository ports (T01), safe for concurrent
use. The persistence behind the whole slice.

## Context

- Ports: [T01](../phase-01-ports/T01-repo-ports.md).
- Concurrency contract: [ADR 0008](../../adr/0008-aggregate-concurrency-contract.md) — serialize RMW.
- Uniqueness: [ADR 0009](../../adr/0009-cross-aggregate-uniqueness-constraints.md).

## Design

```go
type Store struct {
    mu       sync.Mutex
    users    map[domain.UserID]*domain.User
    byEmail  map[string]domain.UserID          // unique index
    creds    map[domain.UserID]*domain.PasswordCredential
    sessions map[string]*domain.Session         // key: hex(TokenHash)
    tokens   map[string]*domain.VerificationToken
}
```

One `Store` can expose the 4 repo interfaces (embed or method-set), or split into
`userRepo`, `sessionRepo`, ... sharing one `*Store`. Either works.

## Steps

1. `internal/adapter/memory/store.go`, package `memory`.
2. Hold one mutex; every method locks for the whole read-modify-write.
3. **Store copies, not caller pointers** — reconstitute or deep-copy on read/write
   so callers can't mutate stored aggregates behind the lock. Use the domain
   `Reconstitute*` constructors on read.
4. Unique email: `Create` checks `byEmail`, returns `port.ErrEmailTaken`.
5. Verification `Create`: scan + mark prior unconsumed (user,purpose) consumed/deleted
   before inserting (ADR 0009 partial-unique-index behaviour, done in-process).
6. Not-found returns the port sentinels from T01.
7. Tests: dup email, token invalidation, find-by-hash hit/miss, revoke-all.

## Notes

- TokenHash isn't comparable as a map key (holds a slice) → key on
  `hex.EncodeToString(h.Bytes())`.
- Defensive copy matters: domain getters already copy slices, but the aggregate
  pointer itself must not be shared mutably — reconstitute on the way out.
- Single global mutex is fine for the slice; per-key locking is a later optimization.
