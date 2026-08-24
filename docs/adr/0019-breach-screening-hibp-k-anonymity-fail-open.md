# 0019. Breach screening via HIBP k-anonymity, failing open by default

- Status: Accepted
- Date: 2026-08-23
- Implements: the breach-screen port declared but stubbed in
  [0011](0011-nist-aligned-default-no-composition-rules.md)

## Context

[ADR 0011](0011-nist-aligned-default-no-composition-rules.md) followed NIST
SP 800-63B in dropping character-composition rules, on the explicit trade that
breach screening replaces them. The screening half was never built: the wiring
used a no-op that accepts everything, so the policy has been running with the
composition rules removed and nothing put in their place. `password1` passes
today.

Two things had to be decided to close that: how to check a password against a
corpus without handing the password to a third party, and what to do when the
third party cannot be reached.

## Decision

### The check

We will use Have I Been Pwned's Pwned Passwords **range API** with k-anonymity.

- `SHA-1(password)`, uppercase hex. The first 5 characters are sent as
  `GET /range/{prefix}`; the remaining 35 are matched **locally** against the
  ~800 suffixes the endpoint returns. The password never leaves the process, and
  a 5-character prefix covers hundreds of thousands of candidates, so the query
  identifies a bucket rather than a password.
- `Add-Padding: true`, so response length does not narrow down which prefix was
  asked for. Padding arrives as plausible suffixes with a count of `0`; those are
  skipped, because treating one as a hit would reject a password on deliberate
  noise.
- SHA-1 is HIBP's index into a public dataset, not a security primitive here. Its
  collision weakness does not affect a membership test, and this is unrelated to
  how passwords are stored — [ADR 0007](0007-password-hashing-prehash-bcrypt-argon2id.md)
  keeps that decision.
- Stdlib only (`net/http`, `crypto/sha1`); no new module dependency.
- The `*http.Client` is injected, so the timeout is set and visible at the wiring
  site (default 3s) and tests use a stub transport. `make check` never touches
  the network.

### The failure mode

We will **fail open** by default: a check that could not be completed accepts the
password, with a WARN log naming the transport error and never the password.

- Fail-open's cost: an attacker who can block or delay egress downgrades the
  deployment to no screening.
- Fail-closed's cost: a third party's outage stops registration and password
  changes entirely.

For this project the second is worse. A total outage of account creation is
certain and immediate whenever HIBP has a bad day; the downgrade requires an
attacker who already controls the deployment's network egress, and who at that
point has better options. The choice is `AUTH_SCREENER_FAIL_OPEN`, so a
deployment with a different risk profile flips it without a code change.

The policy lives in a named wrapper, `screener.FailOpen`, applied at the
composition root — **not** as a swallowed error inside the adapter or a use-case.
The port's contract stays honest ("returns another error if the check could not
be completed; the caller decides"), the decision is visible in the wiring, and
removing the wrapper is all it takes to fail closed.

### Selection

`AUTH_PASSWORD_SCREENER` is `noop` (default) or `hibp`. The default keeps a fresh
checkout and CI offline. An unrecognised value is a startup error, never a
silent fall back to the no-op — a typo must not disable screening. Running with
`noop` logs a WARN at startup saying the policy is weaker than ADR 0011 intends.

## Consequences

- ADR 0011's trade finally holds, but only where `AUTH_PASSWORD_SCREENER=hibp` is
  set. Anywhere it is not, the password policy is exactly as weak as it has been;
  the startup warning is what stops that being invisible.
- Registration, password change, and password reset now depend on an outbound
  network call on the request path, bounded by the client timeout and the
  caller's context. Latency is a third party's to control.
- The privacy claim rests on one line of code — the prefix/suffix split in
  `hibpDigest`. `TestHIBPSendsOnlyThePrefix` asserts the request target contains
  neither the suffix, the full hash, nor the password, so a refactor that widens
  what is sent fails the build rather than leaking quietly.
- Screening runs on the NFC-normalized plaintext, the same form that is validated
  and hashed (see `passwordPipeline`), so a password cannot pass the screen in
  one encoding and be stored under another.
- Not done, deliberately: no caching of negative results. At this volume one call
  per password change is acceptable, and a cache would need its own invalidation
  story. Revisit if the call rate ever justifies it.
- HIBP's range endpoint needs no API key. If that changes, or if the dependency
  on a third party becomes unacceptable, the alternative is a local Pwned
  Passwords dump behind the same port — an adapter swap, with no use-case
  touched.
