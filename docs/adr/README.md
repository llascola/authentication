# Architecture Decision Records

Each ADR captures one significant decision: the context, the choice, and its
consequences. ADRs are immutable once **Accepted** — to change a decision, add a
new ADR that supersedes the old one (and update the old one's Status line to
`Superseded by NNNN`).

Format: lightweight [MADR](https://adr.github.io/madr/). Filename
`NNNN-kebab-title.md`. Use `0000-template.md` as the starting point.

| ADR | Title | Status |
|-----|-------|--------|
| [0001](0001-strict-authn-only-ddd-layering.md) | Strict AuthN-only server, DDD layering | Accepted |
| [0002](0002-inject-clock-via-now-parameter.md) | Inject the clock via an explicit `now` parameter | Accepted |
| [0003](0003-new-vs-reconstitute-constructors.md) | Two constructors: `New*` validates, `Reconstitute*` trusts | Accepted |
| [0004](0004-typed-per-kind-credentials.md) | Typed-per-kind credentials behind a sealed interface | Accepted |
| [0005](0005-verification-token-one-aggregate-purpose-enum.md) | One VerificationToken aggregate + Purpose enum | Accepted |
| [0006](0006-password-length-and-unicode.md) | Password length cap (128 runes) and Unicode handling | Accepted |
| [0007](0007-password-hashing-prehash-bcrypt-argon2id.md) | Password hashing: pre-hash bcrypt or argon2id | Accepted |
| [0008](0008-aggregate-concurrency-contract.md) | Aggregates assume serialized read-modify-write | Accepted |
| [0009](0009-cross-aggregate-uniqueness-constraints.md) | Cross-aggregate uniqueness & constraints (repository layer) | Accepted |
| [0010](0010-account-lifecycle-lockout-roles.md) | Account lifecycle: status transitions, lockout policy, role set | Proposed |
