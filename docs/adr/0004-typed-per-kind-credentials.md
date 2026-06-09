# 0004. Typed-per-kind credentials behind a sealed interface

- Status: Accepted
- Date: 2026-06-03

## Context

A `User` can authenticate by several mechanisms: password, OAuth link, OTP/TOTP,
WebAuthn passkey. These share an identity (they reference a `User` by ID) but
their data differs sharply — a password has a hash, an OAuth link has a provider
and subject, a passkey has a public key and a signature counter. We need a model
that can hold any kind, dispatch verification to the right crypto, and not
invite illegal field combinations.

The obvious alternative is one blob struct: `Credential{ kind, secret []byte,
... }` with nullable fields per kind.

## Decision

We will model each credential kind as its **own concrete type**
(`PasswordCredential`, `OAuthCredential`, `OTPCredential`,
`WebAuthnCredential`), each carrying exactly the fields it needs, unified by a
**sealed `Credential` interface**. The interface is closed via an unexported
`sealedCredential()` marker method, so the set of kinds is fixed and
compiler-checked.

Data is concrete and compiler-guarded; **behavior is abstract and swappable**.
Verification is not on the credential — it lives behind the `Authenticator` port
in `internal/port`, with implementations in infrastructure that own the crypto
(bcrypt compare, TOTP validation, OAuth exchange, signature verification),
selected by `cred.Type()`.

Rule of thumb that follows from this: **use a sum type (typed-per-kind) when the
fields diverge; use an enum when the shape is identical** (see ADR 0005).

## Consequences

- Illegal combinations (an OAuth credential with a password hash) are
  unrepresentable; the field shape documents each kind.
- Adding a kind means adding a type and an `Authenticator` impl — the sealed
  interface forces every exhaustive switch to be revisited.
- No nullable-field smell, no runtime "which fields are set for this kind?"
  checks.
- Less suited to a large or plugin-defined open set of kinds; for this fixed,
  small set the trade is firmly worth it.
