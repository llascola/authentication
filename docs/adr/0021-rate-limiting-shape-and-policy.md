# 0021. Rate limiting: port shape, keying, and failure policy

- Status: Accepted
- Date: 2026-08-23
- Closes: the "rate-limiting login and forgot-password is deferred" note in
  [0015](0015-http-edge-security-posture.md)

## Context

Four routes are cheap to call and expensive to serve:

| Route | What an attacker gets without a limit |
|-------|----------------------------------------|
| `POST /auth/login` | Password spraying. Per-account lockout ([ADR 0010](0010-account-lifecycle-lockout-roles.md)) does nothing against one guess each against ten thousand accounts |
| `POST /auth/register` | Account-creation floods, each costing a bcrypt hash and a mail |
| `POST /auth/password/forgot` | Unlimited mail at any registered address, on our SMTP quota and our domain's sending reputation |
| `POST /auth/verify-email/resend` | The same, and the reason [ADR 0020](0020-resend-verification-enumeration-safe-edge-limited.md) would not ship without this one |

## Decision

### Port shape

```go
Allow(ctx context.Context, key string) (allowed bool, retryAfter time.Duration, err error)
```

- **The key is an opaque string.** The edge decides what goes in it, so the port
  knows nothing about IPs, emails, or routes and does not have to change when the
  keying policy does.
- **One instance per policy**, not a policy argument per call. Configuration then
  lives at the wiring site, and the limit is a property of the object a handler
  holds rather than something every call site must remember to pass correctly.
- **`Allow` consumes.** It is not a peek; one call per attempt.
- **The error return exists for an implementation that can fail** — a
  Redis-backed limiter shared across replicas. The in-process one never returns
  one. Declaring it now is deliberate: widening the interface later would touch
  every call site, and a port that needs widening is worse than one unused return.

### In-memory implementation: token bucket

A fixed-window counter lets a caller spend a full window's quota at the end of
one window and another full quota at the start of the next, so the observed burst
is twice the configured limit across the boundary. A bucket refills continuously,
so the limit holds over every interval — and the time until the next token *is*
the `retryAfter` the caller owes the client, with no second calculation.

Three implementation choices worth recording because each has a failure mode:

- **Idle buckets are swept on write, at most once per window.** Every distinct
  key allocates, so an attacker varying the key mints an entry per request and the
  map grows without bound. A bucket idle for a full window is back at capacity and
  therefore indistinguishable from an absent one, which is what makes reclaiming
  it safe. Sweeping on write avoids a background goroutine with a lifecycle to
  manage.
- **A backwards clock step is treated as zero elapsed.** An NTP correction must
  not subtract tokens and throttle an innocent caller for the size of the step.
- **Constructor arguments clamp toward the restrictive end**, never the permissive
  one. A throttle misconfigured tight is visible the moment someone is throttled;
  one misconfigured loose is a silent hole.

### Keying

Every protected route is keyed by **client IP**, taken from `RemoteAddr` only.
No `X-Forwarded-For`, no `X-Real-IP` — [ADR 0015](0015-http-edge-security-posture.md)
trusts no proxy header, and a key the caller can set is not a limit: one header
line per request would buy a fresh bucket every time. Putting a reverse proxy in
front of this server makes trusting its forwarding header a deliberate,
ADR-recorded change rather than an accident.

Login, forgot, and resend are **additionally** keyed by the submitted email,
canonicalised through `domain.NewEmail` so case and whitespace cannot buy a
second budget. Neither key alone is enough: the IP key misses a mail bomb sourced
from an address pool, and the email key misses a spray across many accounts.

Register is **not** email-keyed. The address on a registration is the caller's to
invent, so a per-email bucket there would bound one made-up string rather than
anything real.

What the email key does and does not bound is worth stating exactly, because it
is easy to overclaim. It bounds **how much forgot/reset and resend mail one
registered address can be made to receive**. It does not bound what a *mailbox*
receives, for two reasons:

- **Registration mails arbitrary addresses.** `POST /auth/register` sends a
  verification link to any well-formed address and is IP-keyed only, so a
  mailbox can be sent 10 mails/hour per source IP, unbounded across IPs, each
  also leaving a `pending` user row behind.
- **Subaddressing defeats canonicalisation.** `domain.NewEmail` trims,
  lowercases, and parses; it does not fold `user+1@` and `user+2@`, or Gmail's
  dots, into one address. Each variant is a distinct key with a distinct bucket
  and the same mailbox at the far end.

Folding those is rejected: the aliasing rules are provider-specific guesswork,
and getting them wrong merges genuinely distinct addresses into one shared
bucket — a denial of service built to prevent one. The residual is treated as
inherent to open registration and listed under Consequences.

`POST /auth/verify-email` and `POST /auth/password/reset` are **deliberately
absent** from the table. Both reject on a token lookup before any bcrypt hash,
mail, or outbound call, so there is no cost for a limiter to bound, and the
tokens themselves are 256-bit opaque values ([ADR 0013](0013-opaque-token-generation-and-rehash.md))
where guessing is not a threat a throttle meaningfully changes.

**The key is derived from the submitted value before any account lookup.** The
natural implementation — look the account up, then throttle if found — turns the
limiter into an existence oracle, where "throttled" means "registered". Limiting
first makes a registered and an unregistered address throttle at the same request
with byte-identical responses.

### Limits

| Route | Limit | Why |
|-------|-------|-----|
| login | 10 / minute | A human retries a mistyped password within seconds and gives up; a spray needs sustained volume |
| register | 10 / hour | Cost is CPU and a mail, and a person registers once |
| forgot | 5 / hour | Cost is an actual email; five is generous for a person and a hard ceiling on what one address can be made to receive |
| resend | 5 / hour | Same |

Configurable per policy via `AUTH_RATELIMIT_<ROUTE>_{LIMIT,WINDOW}`. An
explicitly configured `0` is **rejected at startup** rather than clamped:
disabling a throttle should not be something a typo can do, and the two plausible
intentions behind "0" — unlimited, or block everything — should both have to be
spelled out some other way.

### Failure policy: closed

When the limiter cannot answer, the request is **refused** with `503` and a
`Retry-After`, not waved through.

Failing open hands an attacker who can break or overload the limiter the ability
to switch off every throttle in the process at once — precisely when the throttle
matters. Failing closed means a limiter outage is an auth outage, which with the
in-process implementation cannot happen at all, since it never fails. The
decision only starts binding when a networked limiter replaces it, which is why
it is recorded before that happens rather than discovered then.

Note this is the **opposite** choice to [ADR 0019](0019-breach-screening-hibp-k-anonymity-fail-open.md),
which fails open on breach screening. The difference is what the control is worth
when it is absent: a missing breach screen weakens one password, while a missing
rate limit exposes every account to unlimited attempts. The costs are not
symmetric, so the defaults should not be either.

## Consequences

- Over-limit responses are `429` with a `Retry-After` in delta-seconds, rounded
  up and never below 1 — a `Retry-After` of 0 invites an immediate retry that is
  certain to be refused. Both `429` and `503` are assigned in the central error
  map alongside every other status, keeping enumeration safety auditable in one
  place. `Retry-After` describes the limiter, not the account, so it leaks
  nothing.
- The check runs before the handler, so a denied request costs no bcrypt
  comparison, no repository read, and no mail. Login's dummy-hash timing
  equalization is skipped on a denial, which is fine: a `429` is not a credential
  answer.
- **The limits are per-process.** N replicas enforce N independent limits, so the
  effective limit is N times the configured one. Acceptable for the current
  single-process deployment and the reason the port carries an error return;
  moving to Redis is an adapter swap and a config change, not a redesign.
- **The email key on login is a targeted lockout, and we accept it.** Ten login
  attempts a minute against a victim's address — from any source, with no
  password knowledge and no account needed beyond knowing the address — empty
  that address's bucket and the owner's own login answers `429`. This is the
  price of the key that catches a distributed spray at one account, and every
  scheme that keys on the account identifier pays it. Two things bound the
  damage: the lockout is per-window rather than sticky (unlike the per-account
  lockout of [ADR 0010](0010-account-lifecycle-lockout-roles.md), nothing
  accumulates), and it costs the attacker sustained traffic to hold.
  - Not fixed here, but recorded as the way out: `Limits.Login` is currently a
    *single* limiter instance used with both key functions, so the IP and email
    buckets necessarily share one limit and window. Splitting it into separate
    policies would let the email budget run looser than the IP budget, so a lone
    attacking IP exhausts its own bucket well before the victim's. That is a
    config, `Limits`, and wiring change, deliberately deferred rather than done
    silently.
- **Mail to a mailbox is not bounded** — only mail to a registered address is.
  See the Keying section: registration mails arbitrary addresses under an
  IP-only key, and subaddressing yields unlimited distinct keys for one mailbox.
  Bounding it properly means rate-limiting *account creation itself* (invite
  codes, proof of work, a CAPTCHA) rather than tuning a limiter, which is a
  product decision this project has not taken.
- **A shared egress IP is the known false positive.** Ten logins per minute is
  generous for a person and tight for a NAT'd office at 09:00. The per-route
  config exists so that is tunable without a code change, but a deployment behind
  a large NAT should expect to raise it — and, once a reverse proxy is in front,
  to revisit the `RemoteAddr`-only rule above, since every request will otherwise
  share the proxy's address.
- `NewRouter` panics on a missing limiter. A route silently shipping unthrottled
  is the exact failure this ADR exists to prevent, and a nil check at wiring time
  is cheaper than finding out from an SMTP bill.
- The limiters live on `httpapi.Deps`, whose doc comment previously said
  "use-case services". They are neither use-cases nor `Options`-style settings;
  `Deps` was widened to "the driven dependencies the edge holds" rather than
  adding a third parameter to `NewRouter`. Noted because it slightly stretches
  the layering wording in `CLAUDE.md` — the consumer of this port is the HTTP
  adapter, not `internal/app` — while breaking no import rule.
- A request carrying no usable email (missing, malformed, oversized body) yields
  no email key and is only IP-limited. Not a bypass worth closing: the handler
  rejects such a request without touching the store or the mailer, which is the
  cost this limiter exists to bound. Guessing a fallback key would be worse — one
  bucket shared by every malformed request is one client's to exhaust for
  everyone.
