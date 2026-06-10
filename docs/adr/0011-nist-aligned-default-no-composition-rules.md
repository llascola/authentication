# 0011. NIST-aligned default password policy: no composition rules + breach-screen port

- Status: Accepted
- Date: 2026-06-10

## Context

ADR 0006 set the password length cap (128 runes) and Unicode handling, citing
NIST SP 800-63B and OWASP. But `DefaultPasswordPolicy` then turned on
character-composition rules (require upper + lower + digit) — exactly what the
same standard tells verifiers *not* to do:

> Verifiers SHOULD NOT impose other composition rules (e.g., mixtures of
> different character types) for passwords. — NIST SP 800-63B

This was a real divergence from the cited authority, unexplained. Concretely the
old default rejected a strong passphrase (`correct horse battery staple` — no
digit, no uppercase) while accepting the weaker `Abc12345defg`.

NIST drops composition rules *because* it assumes the verifier screens candidate
passwords against a corpus of known-breached passwords. The two are a package:
"no class rules **but** block known-pwned passwords." Length plus breach
screening is what actually buys security; forced classes mostly steer users
toward predictable, attacker-modelled patterns (`Password1!`).

The domain is dependency-free and must stay so; a breach screen needs I/O and
`context`, which cannot live in `internal/domain`.

## Decision

- **The default imposes no composition rules.** `DefaultPasswordPolicy` now
  returns `NewPasswordPolicy()` with no `Require*` options: 12-128 runes,
  length-only. It accepts long passphrases that the old default wrongly rejected.
- **Composition stays available, opt-in.** The `RequireUpper/Lower/Digit/Symbol`
  options are unchanged. Deployments under regimes that mandate class rules
  (PCI-DSS, some SOC2 audits) opt back in explicitly:
  `NewPasswordPolicy(RequireUpper(), RequireLower(), RequireDigit())`. The engine
  takes no side; only the default does, and it sides with NIST.
- **The breach-screening control is a port, not a domain rule.** A new
  `port.PasswordScreener` interface (`Screen(ctx, plaintext) error`, sentinel
  `ErrPasswordBreached`) declares the contract; no adapter is built yet. The
  application layer invokes it after `PasswordPolicy.Validate` passes, alongside
  NFC normalization and hashing (ADR 0006, ADR 0007), on the transient plaintext
  that is then discarded. The plaintext never enters a domain entity.

This supersedes the composition-rule default introduced with the password policy;
it does not change ADR 0006's length/Unicode decisions, which stand.

## Consequences

- The default now matches the standard ADR 0006 cites; the documented tension is
  resolved by changing the default, not by justifying a divergence.
- Behavior change: existing callers relying on the old class-requiring default get
  a length-only policy. `TestDefaultPasswordPolicy` is updated to assert no
  composition rules and to accept a passphrase.
- The NIST package is only half-complete until a `PasswordScreener` adapter
  exists (e.g. local Pwned Passwords dump, or HIBP range API with k-anonymity).
  Until then a length-only default with no breach screen is weaker than intended;
  building the adapter is the tracked follow-up.
- Screener implementations must not log or persist the plaintext and should
  prefer k-anonymity range queries over sending a full hash to a third party.
- Adding the port keeps `internal/domain` dependency-free; the I/O-bearing
  contract lives in `internal/port` beside `Authenticator`.
