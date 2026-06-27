# 0013. Opaque token generation and verification re-hash recipe

- Status: Accepted
- Date: 2026-06-27

## Context

Two kinds of bearer secret run through the slice: session tokens and
verification/reset tokens. Both share the same need — a high-entropy secret
shown to the client once, with only a hash stored at rest (see ADR 0005,
`session.go`). Validating a presented secret (a session cookie, a reset link)
requires re-deriving the stored hash the exact same way it was minted, in three
different use-cases (validate-session, verify-email, reset-password). If the mint
recipe and the validate recipe ever drift, every lookup silently fails.

## Decision

We will provide one `port.TokenGenerator` adapter (`crypto.TokenGen`) that owns
the whole recipe:

- **Generate**: 32 bytes from `crypto/rand` → `base64.RawURLEncoding` raw string
  → `SHA-256` of that raw string → `domain.TokenHash`. The raw is returned once
  for delivery; only the hash is persisted. A `crypto/rand` failure is fatal and
  propagated, never masked.
- **Hash(raw)**: the port carries a second method that re-derives the stored
  `TokenHash` from a presented raw secret using the identical recipe. The
  application calls it to validate any presented token without knowing the
  algorithm. `Generate` is implemented in terms of `Hash` so the two cannot drift.
- **The hash is taken over the base64 string** the client actually holds, not the
  underlying random bytes, so validate-session re-hashes the cookie value
  directly.

One generator serves both session and verification tokens; their entropy needs
are identical.

## Consequences

- The mint/validate recipe exists in exactly one place; the three validating
  use-cases agree by construction.
- The application layer stays free of crypto: it depends only on the port, and
  the algorithm (SHA-256, base64url, 32 bytes) is swappable in the adapter.
- Putting `Hash(raw)` on `TokenGenerator` slightly widens the port beyond pure
  generation. The alternative — a separate `TokenHasher` port — was heavier for
  no gain, since the recipe is one unit of knowledge.
- 256 bits of entropy puts brute-force and birthday-collision risk out of scope;
  no per-token uniqueness check is needed at the store.
