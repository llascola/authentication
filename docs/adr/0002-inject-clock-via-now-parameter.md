# 0002. Inject the clock via an explicit `now` parameter

- Status: Accepted
- Date: 2026-06-09

## Context

Many domain operations are time-dependent: token expiry, session idle/absolute
windows, lockout auto-expiry, timestamp stamping. The domain must be
deterministic to test, so the source of "now" matters.

An earlier iteration used a pragmatic-purist split: query methods took a
`now time.Time` parameter (for testable expiry checks) while mutators and
constructors called `time.Now()` internally to avoid boilerplate. This left the
clock half-injected — mutators could not be tested at a chosen instant without
real time, and the rule "does this method take `now`?" had no simple answer.

## Decision

We will inject the clock everywhere. **Every constructor and mutator that needs
the current time takes an explicit `now time.Time` as its first time argument.**
The domain never calls `time.Now()` — there are zero `time.Now()` calls in
`internal/domain`. Callers (application layer) pass the clock in.

This supersedes the earlier "mutators use internal `time.Now()`" approach
(refactored in commit `aed81be`).

## Consequences

- Every time-dependent behavior is testable at an exact instant; tests use a
  fixed `timeFixed()` fixture and pass derived times explicitly.
- One uniform rule, no per-method judgement call: if it touches time, it takes
  `now`.
- Slightly more verbose call sites; the application layer becomes the single
  place that reads the real clock and is responsible for passing a consistent
  `now` through a single operation.
- A future `Clock` port is unnecessary for the domain — the parameter is the
  injection point.
