# authentication

A strict **authentication-only** server in Go, built with Domain-Driven Design.
It models identities, credentials, sessions, and verification — it does **not**
do authorization policy, business features, or user-profile management.

## Commands

```bash
make build      # go build -o bin/<cmd> ./cmd/<cmd>
make test       # go test -race ./...
make vet        # go vet ./...
make lint       # go tool staticcheck ./...
make fmt        # gofmt -w (write); fmt-check fails if unformatted
make check      # fmt-check + vet + lint + test — the full gate, == CI
```

Run `make check` before declaring work done; CI (`.github/workflows/ci.yml`)
runs the same steps. Go 1.25.4. Runtime dependency: `github.com/google/uuid`.
Lint is staticcheck, pinned as a `tool` directive in `go.mod`.

## Architecture

Dependencies point inward. The domain is the center and imports nothing of ours.

```
cmd/server          process entrypoint + wiring (currently a stub)
internal/domain     entities, value objects, aggregates, business rules
internal/port       driven-port interfaces the app needs (no implementations)
internal/adapter    infrastructure: db, http, crypto (not built yet)
internal/app        use-case orchestration (not built yet)
```

Import rules:

- `internal/domain` imports only stdlib + `google/uuid`. Never port/app/adapter.
- `internal/port` imports `internal/domain` only. Never the reverse.
- Adapters implement port interfaces; wiring happens in `cmd/server`.

When adding code, put it in the layer that matches its job and respect the
arrow. If a new driven dependency is needed (a repository, a clock, a mailer),
declare the **interface in `internal/port`** and implement it in an adapter.

## Domain conventions (do not break)

- **Two constructors.** `New*` builds fresh state: validates every argument,
  stamps timestamps, returns an error on bad input. `Reconstitute*` hydrates a
  trusted aggregate from storage: no validation. Adapters use `Reconstitute*`;
  application code creating new state uses `New*`.
- **Inject time.** Every constructor/mutator needing the clock takes an explicit
  `now time.Time`. The domain never calls `time.Now`. Keep it that way.
- **Private fields, behavior-rich aggregates.** Mutate only through methods that
  preserve invariants. No exported struct fields on aggregates.
- **Defensive copies.** Getters returning a slice or byte value return a copy
  (`slices.Clone`, or `append([]byte(nil), v...)`). Never hand out internal refs.
- **Sealed Credential.** `Credential` is a sealed interface (unexported
  `sealedCredential()` marker). Add a new credential kind as its own concrete
  type implementing the interface — do not widen an existing one into a blob.
- **Sentinel errors.** Declare exported `Err*` values with `errors.New`, message
  prefixed `domain: `. Callers use `errors.Is`; wrap with `%w` for context.
  Multi-violation validators aggregate with `errors.Join`.
- **Reference by ID.** Aggregates reference other aggregates by their ID type,
  never by embedding the other aggregate.

## Concurrency

Aggregates are **not** safe for concurrent use. Infrastructure must serialise
read-modify-write on a single aggregate (row lock or optimistic-version retry).
Hotspots: session touch/revoke, lockout counter, recovery-code consume.

## Testing

Tests live beside code in package `domain_test` (black-box). Each file has
`must*` helpers for value-object construction and a fixed-time fixture
(`timeFixed`). New aggregates/mutators need: a happy path, each rejected input
(asserted with `errors.Is`), and getter-isolation tests for any slice/byte
getter. Run `make check` before declaring done.

## Decisions

Significant decisions live as ADRs in `docs/adr/` (see its README index). Read
the relevant ADR before changing a locked decision; to reverse one, add a new
ADR that supersedes it rather than editing the old one. Current set covers:
layering (0001), clock injection (0002), New*/Reconstitute* (0003), typed
credentials (0004), VerificationToken (0005), password length/Unicode (0006),
password hashing (0007), concurrency contract (0008), cross-aggregate
uniqueness/constraints (0009).

## Commits

Conventional Commits: `Type(scope): subject`. Types seen in history: `Feat`,
`Fix`, `Refactor`, `chore`. Scope is the area, e.g. `domain`, `password_policy`.
