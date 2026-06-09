# 0001. Strict AuthN-only server, DDD layering

- Status: Accepted
- Date: 2026-06-03

## Context

We are building an identity/authentication server. Authentication (proving who
you are) and authorization (deciding what you may do) are distinct concerns that
tend to get tangled into one service, which then owns everything and is hard to
evolve. We want a clean, testable core and freedom to move infrastructure
choices later.

## Decision

We will build a **strict authentication-only** server. Authorization policy
(a PDP) is explicitly out of scope and will be a separate service later. Roles
are kept on `User` only as a *carried claim* — read live, never snapshotted into
a `Session` — because no AuthZ service exists yet and they are useful to expose.

We will use a Domain-Driven, dependency-inverted layout under `internal/`:

```
cmd/server          process entrypoint + wiring
internal/domain     entities, value objects, aggregates, business rules
internal/port       driven-port interfaces the app depends on
internal/adapter    infrastructure adapters (db, http, crypto)   [future]
internal/app        use-case orchestration                        [future]
```

The dependency arrow always points inward. `internal/domain` imports only the
standard library and `github.com/google/uuid`; it contains no crypto, no I/O,
and no transport or storage concerns. Driven dependencies are declared as
interfaces in `internal/port` (which imports domain, never the reverse) and
implemented by adapters wired in `cmd/server`.

The domain is **rich, not anemic**: aggregates have private fields and behavior
methods that preserve invariants. Tests are black-box (`domain_test` package),
table-driven, ~95% coverage.

## Consequences

- The domain stays pure and fast to test; it can be reasoned about without a
  database or HTTP server.
- Swapping infrastructure (bcrypt↔argon2id, Postgres↔other) touches adapters
  only, never the domain.
- Authorization cannot be added here later by accident — it would violate the
  scope and belongs in the separate PDP.
- More upfront structure (ports, two constructor styles) than a CRUD app needs;
  justified by the security-critical, long-lived nature of the core.
- Roles-as-claim means a live role change is reflected immediately; consumers
  must not cache roles from a session.
