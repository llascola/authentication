# 0020. Resend-verification: enumeration-safe, edge-limited, no per-user cooldown

- Status: Accepted
- Date: 2026-08-23

## Context

Verification tokens live 24h ([ADR 0005](0005-verification-token-one-aggregate-purpose-enum.md)),
and `Register` commits the user, credential, and token *before* it calls the
mailer. A lost, bounced, or failed send therefore stranded the account with no
way out at any layer:

- login refuses it — it requires `StatusActive`;
- re-registering hits `ErrEmailTaken`, which `Register` maps to `nil` for
  enumeration safety, minting nothing;
- forgot-password issues a `PurposePasswordReset` token, and `VerifyEmail`
  rejects a wrong-purpose token.

The address became permanently unusable. A resend path was not a feature but the
missing exit from a dead end.

Adding it raises two questions that are easy to get wrong: what a resend reveals
about an address, and how a route that sends mail on demand is kept from being a
mail cannon.

## Decision

### One outward result, four inward branches

`ResendVerification` returns `nil` and the endpoint answers `202` with a fixed
body in **every** case. A token is minted and mailed only when the account is
registered, still `StatusPending`, and unverified. The other cases — malformed
address, unknown account, already verified, past `StatusPending` — issue nothing
and are indistinguishable from success.

This mirrors `ForgotPassword` exactly, deliberately: two routes with the same
enumeration exposure should not have two different-looking implementations, or
the next reader has to work out whether the difference is meaningful.

Creating the token invalidates any prior unconsumed verification token for the
user ([ADR 0009](0009-cross-aggregate-uniqueness-constraints.md), enforced by the
repository), so only the newest mail works.

### Throttling at the edge only

The route is limited by client IP **and** by submitted email
([ADR 0021](0021-rate-limiting-shape-and-policy.md)), at 5 per hour. We will
**not** add a per-user cooldown in the use-case.

The per-email key already bounds what matters — how much mail one address can be
made to receive, no matter how many sources ask. A use-case cooldown would
duplicate that while needing its own state and its own tests.

What a per-user cooldown *would* add over the edge limit is durability: the
in-memory limiter is per-process and resets on restart, whereas state read from
the store is shared across replicas and survives. That is a real difference, and
the reason this is recorded as a revisit rather than a rejection. If it is ever
needed, the cheap version needs no new schema: the most recent unconsumed
`PurposeEmailVerify` token already carries `CreatedAt()`, which is a cooldown
source sitting in the store already.

## Consequences

- An account whose verification mail never arrived is recoverable by the user,
  without operator involvement, which is the whole point.
- The endpoint mails an attacker-chosen address on request. It is safe **only**
  behind the rate limits in ADR 0021; the two shipped together on purpose and
  neither half should be deployed alone.
- Enumeration safety here is a property of four branches returning the same
  thing, which is exactly the kind of thing that rots under later edits. The
  tests assert the branches are identical rather than asserting each one
  individually, so a new branch that returns something different fails.
- Restarting the process resets the edge limit, so the effective ceiling on mail
  to one address is per-process-lifetime, not absolute. Accepted while the
  limiter is in-memory; revisit with a shared limiter or the token-timestamp
  cooldown above.
- This does **not** fix the underlying ordering in `Register` — state is still
  committed before the mail is sent. It is the escape hatch for that, not a
  repair of it. An outbox or a retry is a separate question, deliberately not
  answered here.
