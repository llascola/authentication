# 0014. NFC password normalization behind a Normalizer port

- Status: Accepted
- Date: 2026-06-27

## Context

ADR 0006 requires passwords to be NFC-normalized before hashing or comparison,
so two visually identical inputs entered with different code-point sequences
(composed vs decomposed) authenticate the same. Correct NFC needs Unicode tables
— in practice `golang.org/x/text/unicode/norm`. But:

- The domain must import only stdlib + `google/uuid` (ADR 0001); it cannot take a
  Unicode-table dependency.
- The project had a stated single-runtime-dependency posture. Adding `x/text`
  changes that, and the question was where the dependency is allowed to live.

The realistic options were: add `x/text` and call it directly from the
application; do a minimal/stub normalization for the slice; or hide the real
implementation behind a port.

## Decision

We will define a `port.Normalizer` interface (`Normalize(string) string`, pure,
no I/O) and implement it with `x/text` in a dedicated `internal/adapter/text`
adapter (`text.NFC`). The application depends only on the port and applies
normalization to the transient plaintext inside the shared password pipeline
(normalize → policy-validate → breach-screen → hash); the same normalized form
is validated and hashed, so a password can never pass the checks in one encoding
and be stored under another. The domain and application packages take no
Unicode dependency.

## Consequences

- The `x/text` dependency is confined to one adapter, wired at `main`. The domain
  stays pure; the application stays dependency-free and unit-testable without
  Unicode tables. CLAUDE.md's runtime-dependency note was updated to record the
  two adapter-confined deps (`x/text`, `x/crypto`).
- Normalization is swappable (e.g. to a stricter NFKC, or a stubbed identity for
  a constrained build) by changing only the adapter.
- One extra interface hop for a one-line call — accepted, because it preserves
  the layering invariant that made adding the dependency palatable at all.
- This ADR refines ADR 0006 (it pins *where* normalization happens); it does not
  supersede it.
