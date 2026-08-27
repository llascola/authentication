# 0023. Client IP from a counted X-Forwarded-For hop, off by default

- Status: Accepted
- Date: 2026-08-27
- Refines: [0015](0015-http-edge-security-posture.md), whose "no proxy header is
  trusted" rule stays the default and becomes explicitly configurable
- Motivated by: [0021](0021-rate-limiting-shape-and-policy.md), which recorded
  this as something to revisit "once a reverse proxy is in front"

## Context

`ipKey` derived the rate-limit key from `r.RemoteAddr` alone, and
[ADR 0015](0015-http-edge-security-posture.md) justified that correctly: a
forwarding header is attacker-settable, and a key the caller controls is not a
limit. One extra header line per request would buy a fresh bucket every time.

The problem is that the deployment invalidates the premise. This server speaks
plain HTTP and defaults `CookieSecure` to true, so a `Secure` cookie is unusable
unless something terminates TLS in front of it. From that moment the TCP peer of
every request is the proxy:

```
ipKey(user A)   → "ip:10.0.1.5"
ipKey(user B)   → "ip:10.0.1.5"
ipKey(attacker) → "ip:10.0.1.5"
```

One bucket, shared by everyone. Against the defaults of
[ADR 0021](0021-rate-limiting-shape-and-policy.md) that is ten logins per minute
and ten registrations per hour **for the entire user base**. It fails closed, so
it is an availability failure rather than a bypass — but it needs no attacker,
arrives with the first successful day of traffic, and while it is happening the
throttle has stopped bounding anything an attacker does.

`deviceFromRequest` had the same defect for a different reason: every session
would record the load balancer's address, making `DeviceInfo` uniform and
useless for telling one device from another.

The naive repair is worse than the disease. `X-Forwarded-For` is append-only and
the *client* writes the first entry:

```
Client sends:       X-Forwarded-For: 1.2.3.4
Proxy appends:      X-Forwarded-For: 1.2.3.4, 203.0.113.9
                                              ^^^^^^^^^^^ written by our proxy,
                                                          from the connection it
                                                          actually accepted
```

Reading the leftmost value reads the forgery. Everything to the left of our own
infrastructure's entries is the caller's to invent; everything to the right of
them is not.

## Decision

We will resolve the client address in one function, `clientIP(r, hops)`, shared
by the rate limiter and by the session's `DeviceInfo` — these are the only two
consumers of "who is calling", and letting them disagree would mean the throttle
counting one address while the session recorded another.

`hops` comes from `AUTH_TRUSTED_PROXY_HOPS` and **defaults to 0**, which
consults no forwarding header at all and preserves ADR 0015's posture exactly.
A non-zero value is the operator stating how many proxies *they* operate; the
address taken is that many entries from the **right** of the joined
`X-Forwarded-For` list. Valid range `[0,8]`, rejected at startup outside it.

Three details are load-bearing:

- **Header lines are joined before counting.** Repeated header lines are
  semantically one list, but Go keeps them separate. An implementation reading
  only the first line could be fed a second line by the caller to shift the
  indices and move a forged entry into the trusted slot.
- **Every failure falls back to `RemoteAddr`.** No header, fewer entries than
  the configured chain, an entry that does not parse as an IP: all resolve to
  the peer address. A request that did not arrive the way the configuration
  describes is treated as though the header were not trusted at all.
- **The resolution in force is logged at startup.** Both misconfigurations are
  silent from inside the process, so the composition root states which mode is
  active rather than leaving it to be inferred from a rate-limit graph weeks
  later.

## Consequences

- **The network assumption is now part of the configuration.** Hop counting is
  sound only while the application port is unreachable except through those
  proxies. If anything can connect directly, it writes the whole header itself,
  there is no infrastructure-written entry on the right, and a non-zero setting
  hands that caller a fresh bucket per request — the exact bypass the default
  prevents. This is recorded in the config block comment, in `clientIP`, and in
  the startup log, because it is not checkable from inside the process.
- **Both misconfigurations are silent, in opposite directions.** Too high reads
  a forged entry. Too low reads an internal proxy address and silently restores
  the single-bucket outage. Neither raises an error; the value is a claim about
  topology that only the operator can verify.
- **A safer deployment exists and is worth preferring.** A proxy configured to
  *replace* rather than append — nginx `proxy_set_header X-Forwarded-For
  $remote_addr` instead of `$proxy_add_x_forwarded_for` — discards whatever the
  client sent, so the header carries exactly one value and `hops=1` is
  forgery-proof regardless of direct reachability. Managed load balancers mostly
  append (AWS ALB appends; Cloudflare appends to XFF alongside its own
  single-valued `CF-Connecting-IP`), which is why the general mechanism is hop
  counting rather than "trust the header".
- **What this deliberately does not do:** verify that the peer is actually one
  of our proxies. An allowlist of proxy CIDRs would make a non-zero setting safe
  even on a directly reachable port, at the cost of a second env var and a
  second thing to keep in sync with the network. It is the obvious next step if
  this server is ever exposed both directly and through a proxy; until then, the
  network-level fix (bind to a private interface, use a security group) is the
  better place for that guarantee.
- Only `X-Forwarded-For` is read. `X-Real-IP` carries no chain, so it cannot be
  counted and cannot be made safe by this mechanism; RFC 7239 `Forwarded` is not
  implemented because nothing in the intended deployment emits it.
- `DeviceInfo` now records the resolved address, so session device data becomes
  meaningful behind a proxy once the setting is correct — and stays uniformly
  the proxy's address while it is not.
