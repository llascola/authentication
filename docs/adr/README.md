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
| [0010](0010-account-lifecycle-lockout-roles.md) | Account lifecycle: status transitions, lockout policy, role set | Accepted |
| [0011](0011-nist-aligned-default-no-composition-rules.md) | NIST-aligned default password policy + breach-screen port | Accepted |
| [0012](0012-repository-port-contract.md) | Repository port contract: sentinel not-found, adapter-side constraints, copy-on-store | Accepted |
| [0013](0013-opaque-token-generation-and-rehash.md) | Opaque token generation and verification re-hash recipe | Accepted |
| [0014](0014-nfc-normalization-behind-port.md) | NFC password normalization behind a Normalizer port | Accepted |
| [0015](0015-http-edge-security-posture.md) | HTTP edge security posture: cookies, enumeration safety, timing, session revocation | Accepted (revocation part superseded by 0017) |
| [0016](0016-mailer-delivery-and-link-assembly.md) | Mailer delivery: in-process SMTP, adapter-assembled links, secret crosses to provider | Accepted |
| [0017](0017-keep-initiating-session-on-password-change.md) | Keep the initiating session on an authenticated password change | Accepted |
| [0018](0018-csrf-double-submit-bound-to-session.md) | CSRF: double-submit token bound to the session by HMAC | Accepted |
| [0019](0019-breach-screening-hibp-k-anonymity-fail-open.md) | Breach screening via HIBP k-anonymity, failing open by default | Accepted |
| [0020](0020-resend-verification-enumeration-safe-edge-limited.md) | Resend-verification: enumeration-safe, edge-limited, no per-user cooldown | Accepted |
| [0021](0021-rate-limiting-shape-and-policy.md) | Rate limiting: port shape, keying, and failure policy | Accepted |
| [0022](0022-process-level-edge-hardening.md) | Process-level edge hardening: server deadlines, response headers, liveness probe | Accepted |
| [0023](0023-trusted-proxy-hops-for-client-ip.md) | Client IP from a counted X-Forwarded-For hop, off by default | Accepted |
