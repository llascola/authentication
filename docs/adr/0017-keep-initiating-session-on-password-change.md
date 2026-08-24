# 0017. Keep the initiating session on an authenticated password change

- Status: Accepted
- Date: 2026-08-23
- Supersedes: the "full session revocation on credential change" decision in
  [0015](0015-http-edge-security-posture.md), for ChangePassword only

## Context

[ADR 0015](0015-http-edge-security-posture.md) decided that both `ChangePassword`
and `ResetPassword` revoke **every** session for the user, including the one that
initiated the change. Its Consequences section named that a deliberate strictness
trade-off and recorded `RevokeAllExcept` as the known follow-up.

The two flows are not the same event, and treating them identically is what makes
the strict rule look wrong in one of them:

- `ChangePassword` is performed from a live, authenticated session by someone who
  proves the **current** password. That is two independent pieces of evidence that
  the actor is the account holder.
- `ResetPassword` is performed by whoever holds an emailed token and does **not**
  know the current password. It is the recovery path, frequently taken *because*
  something went wrong.

The cost of the strict rule falls entirely on the first case. A user who changes
their password is immediately logged out of the page they were standing on, with
no signal distinguishing "you did this correctly" from "something went wrong".
That is the kind of friction that teaches people not to change passwords —
which costs more security than the rule buys.

The security argument 0015 made still holds, but only partially. A password
change *is* a reason to distrust sessions: an attacker holding a stolen cookie
should lose it. That argument applies to every session except the one presenting
current-password proof right now.

## Decision

We will spare the initiating session on an authenticated password change, and
only that one.

- `port.SessionRepository` gains
  `RevokeAllExcept(ctx, userID, keep domain.TokenHash, now, reason)`. It takes the
  **stored hash**, never a raw bearer token: raw tokens do not reach a repository
  ([ADR 0013](0013-opaque-token-generation-and-rehash.md)).
- A zero or unmatched `keep` spares nothing, degrading to revoke-everything.
  The degenerate case fails toward revoking too much, never too little, so a
  caller that omits its session cannot accidentally preserve one.
  `RevokeAllForUser` is implemented as exactly this call.
- `app.Identity` carries `SessionHash`, populated by `ValidateSession` from the
  session it resolved. `ChangePassword` takes the whole `Identity` rather than a
  bare user id, so the acting user and the acting session cannot be mismatched at
  a call site.
- `ChangePassword` calls `RevokeAllExcept` with the caller's session hash.
- `ResetPassword` keeps calling `RevokeAllForUser` — **unchanged**. There is no
  calling session to preserve, and the user may be recovering from a compromise.

Everything else in ADR 0015 — cookie attributes, the central error→status map,
login timing equalization, edge hardening — stands as written.

## Consequences

- A password change no longer interrupts the user mid-action, while still
  evicting every other session, which is the part that actually removes an
  attacker.
- The spared session keeps whatever was minted for it before the credential
  changed. Once CSRF tokens exist ([T29](../plan/phase-06-flow-completion/T29-csrf.md)),
  the surviving session's token must be **rotated** on password change rather
  than carried over — a token issued under the old credential should not outlive
  it. This is the one new obligation this ADR creates.
- Every `port.SessionRepository` implementation now owes two revoke methods.
  Phase 07's Postgres adapter must implement `RevokeAllExcept` with the same
  serialization guarantee ([ADR 0008](0008-aggregate-concurrency-contract.md));
  the port contract test is what keeps the two implementations honest.
- The residual risk we accept: an attacker who has *both* a stolen session and
  the current password can change the password and keep their session. But such
  an attacker can already do anything the account can do, and would simply change
  the password and log in again — sparing their session costs nothing they did
  not already have.
- `ChangePassword`'s signature changed from `(ctx, userID, old, new)` to
  `(ctx, caller Identity, old, new)`. Any future caller must pass an Identity
  that came from `ValidateSession`, not one assembled by hand, or the session it
  names will not be the one doing the work.
