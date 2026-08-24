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
runs the same steps. Go 1.25.13. Runtime dependencies: `github.com/google/uuid`
(domain IDs), plus two confined to single adapters — `golang.org/x/crypto`
(bcrypt, in `adapter/crypto`) and `golang.org/x/text` (NFC, in `adapter/text`,
behind `port.Normalizer`). The domain still imports only stdlib + uuid.
Lint is staticcheck, pinned as a `tool` directive in `go.mod`.

## Architecture

Dependencies point inward. The domain is the center and imports nothing of ours.

```
cmd/server          process entrypoint, composition root, graceful shutdown
internal/domain     entities, value objects, aggregates, business rules
internal/port       driven-port interfaces the app needs (no implementations)
internal/app        use-case orchestration (register, login, verify, reset, …)
internal/adapter    infrastructure, one package per concern:
                      clock      system clock
                      crypto     bcrypt hasher/authenticator, opaque tokens
                      http       the driving HTTP edge (package httpapi)
                      mailer     dev LogMailer + SmtpMailer
                      memory     in-memory repositories (Postgres is Phase 07)
                      ratelimit  in-process token-bucket RateLimiter
                      screener   no-op + HIBP breach screener
                      text       NFC normalizer
internal/config     env-sourced configuration (stdlib only)
```

Import rules:

- `internal/domain` imports only stdlib + `google/uuid`. Never port/app/adapter.
- `internal/port` imports `internal/domain` only. Never the reverse.
- `internal/app` imports domain + port only. Never an adapter.
- Adapters implement port interfaces; wiring happens in `cmd/server`.
- `internal/adapter/http` is the one adapter allowed to import `internal/app`:
  it is the driving side, and it holds edge-level ports (rate limiters) itself.

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

## Plan

The active implementation plan lives as a tree in `docs/plan/` — phases as
folders, one self-contained file per task with YAML frontmatter (`id`, `status`,
`depends_on`, `touches`, `done_when`). Start at `docs/plan/README.md` (vision,
locked decisions, dependency graph); live progress is `docs/plan/STATUS.md`,
regenerated from task frontmatter with `make plan-status`. Each phase gets its own
`phase-0N-*` branch; the plan itself is committed to `main`.

## Decisions

Significant decisions live as ADRs in `docs/adr/` (see its README index). Read
the relevant ADR before changing a locked decision; to reverse one, add a new
ADR that supersedes it rather than editing the old one. Current set covers:
layering (0001), clock injection (0002), New*/Reconstitute* (0003), typed
credentials (0004), VerificationToken (0005), password length/Unicode (0006),
password hashing (0007), concurrency contract (0008), cross-aggregate
uniqueness/constraints (0009), account lifecycle/lockout/roles (0010),
NIST-aligned password default + breach-screen port (0011), repository port
contract (0012), opaque token generation + re-hash (0013), NFC normalization
behind a port (0014), HTTP edge security posture (0015), mailer delivery via
in-process SMTP with adapter-assembled links (0016), keeping the initiating
session on an authenticated password change (0017, superseding that part of
0015), CSRF double-submit bound to the session by HMAC (0018), breach screening
via HIBP k-anonymity failing open (0019), enumeration-safe resend-verification
(0020), and rate-limiting shape/keying/failure policy (0021).

## Commits

Conventional Commits: `Type(scope): subject`. Types seen in history: `Feat`,
`Fix`, `Refactor`, `chore`. Scope is the area, e.g. `domain`, `password_policy`.
