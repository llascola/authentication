# 0005. One VerificationToken aggregate + Purpose enum

- Status: Accepted
- Date: 2026-06-04

## Context

Four flows need a single-use, time-bounded proof-of-possession token:
email-verify, password-reset, magic-link, phone-verify. They are mechanically
identical — issue a secret, store it hashed, expire it, allow one consumption,
reference a `User` by ID. Only two things vary: the time-to-live and the meaning
of the flow. This contrasts with credentials (ADR 0004), where the data per kind
genuinely diverges.

## Decision

We will model a **single `VerificationToken` aggregate** parameterized by a
`Purpose` enum, not a distinct type per purpose, because the field shape is
identical across all four flows.

Supporting decisions:

- **Hash-at-rest.** The aggregate stores a `TokenHash` (reused from the session
  model), never the raw secret. `Consume()` performs lifecycle only; the
  constant-time compare lives in infrastructure.
- **Per-purpose TTL owned by the domain.** A `ttlByPurpose` map (email 24h,
  reset 1h, magic-link 15m, phone 10m) is the single source of truth, exposed
  via `Purpose.TTL() (time.Duration, bool)`. The constructor uses the comma-ok
  result as the purpose-validity check: a new `Purpose` constant without a TTL
  entry fails loudly with `ErrInvalidPurpose` instead of minting a zero-TTL,
  instantly-expired token.
- **References User by ID only**, per the cross-aggregate rule.

## Consequences

- One type, one set of tests, covers all four flows; adding a flow is adding a
  `Purpose` constant plus its TTL entry.
- The comma-ok TTL lookup makes "forgot to set a TTL" a hard failure, not a
  silent security bug.
- Known limitation: the invariant "at most one active token per (userID,
  purpose)" cannot be enforced inside a single aggregate (it can't see its
  siblings). It must be enforced in the repository/app layer
  (invalidate-prior-on-issue, or a unique partial index on unconsumed rows).
  This is now specified as a repository contract in ADR 0009; the
  `VerificationToken` doc comment points there.
