# 0016. Mailer delivery: in-process SMTP, adapter-assembled links, secret crosses to provider

- Status: Accepted
- Date: 2026-07-09

## Context

The password slice ships only a dev-only LogMailer (T09) that logs the raw
token; there is no production delivery. Two questions were open: (1) does email
belong in an authentication-only server at all, and (2) does the raw secret
cross a service boundary, or only a non-secret reference (a link id)?

The server is a personal project at low mail volume — email verification and
password reset only. ADR 0001 keeps this server authentication-only; ADR 0005
gives verification tokens a short per-purpose TTL and single use; ADR 0013
stores only a hash of the token, never the token itself.

## Decision

- **Delivery is in-process over SMTP, not a separate notification service.**
  A production `SmtpMailer` implements the existing `port.Mailer`. No new
  transport service, no message broker. At this volume the operational cost of a
  notification service is not justified.
- **The mailer adapter assembles the link**, not the application layer. The app
  use-cases keep passing only the raw token to `port.Mailer`; the adapter wraps
  it in a configured base URL as `?token=...`. The URL shape is a delivery
  concern and stays in the delivery layer, so `internal/app` gains no knowledge
  of frontend routes.
- **The raw token crosses to the email provider (Flow A).** Because the
  delivered artifact is a clickable link, the provider necessarily sees the
  secret. We accept this rather than build an indirection service. Blast radius
  is bounded by the existing short TTL + single use + hash-at-rest, plus:
  TLS-only transport (STARTTLS, `MinVersion` TLS 1.2), `https`-only link bases,
  and an adapter that logs neither the token nor the link.
- **Provider is pluggable via SMTP config**, defaulting operationally to Resend
  (3,000/mo free, native SMTP, good deliverability). Any SMTP provider works by
  changing configuration only; no code change. Dev and CI keep LogMailer (empty
  `AUTH_SMTP_ADDR`).
- **Dependency-free.** Delivery uses stdlib `net/smtp`, `net/mail`, and
  `crypto/tls`. No new module dependency; the charter's minimal-dependency rule
  holds. `x/crypto` and `x/text` remain the only non-uuid runtime deps, each
  still confined to its own adapter.

## Consequences

- The "MUST NOT log the raw token" clause on `port.Mailer` is now enforced in
  production (SmtpMailer logs nothing); LogMailer remains the sole, dev-only
  exception.
- The email provider is inside the trust boundary for live reset links. This is
  the accepted cost of Flow A; TTL is the primary backstop. If the threat model
  tightens (distrust the provider/broker, or a compliance rule on secret egress),
  the escape hatch is Flow B2: publish an opaque delivery id and point the link
  at an authentication-owned redirect that resolves the token server-side —
  deferred, recorded here.
- `net/smtp` is a frozen stdlib package (PLAIN auth + STARTTLS only). Moving to
  OAuth2, implicit TLS on 465, or multi-provider fan-out would justify adopting a
  maintained SMTP library (e.g. `wneessen/go-mail`) under a superseding ADR.
- Config gains six mailer environment variables with an all-or-nothing rule: a
  partially configured mailer fails at startup, not at first send.
- The SMTP transport is injected behind an unexported function so the adapter's
  message assembly (link, headers, CRLF) is unit-tested without a network; the
  live STARTTLS path is exercised manually/integration, not in unit tests.

## References

- ADR 0001 (authentication-only charter), 0005 (token TTL / single use),
  0013 (hash-at-rest token recipe).
- Extends the T09 stub-mailer decision toward production. Supersedes nothing.
