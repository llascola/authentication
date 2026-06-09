# 0006. Password length cap (128 runes) and Unicode handling

- Status: Accepted
- Date: 2026-06-06

## Context

Passwords must be safe and inclusive: long enough for passphrases, accepting of
non-Latin scripts and emoji, and resistant to silent failures caused by Unicode
normalization mismatches. Length limits expressed in bytes interact badly with
multibyte characters and with the hashing layer (see ADR 0007). This decision
spans the infra/app/front-end layers; the domain stays hasher-agnostic.

## Decision

- **Length cap is 128 runes (code points), not bytes.** This clears the
  NIST 800-63B / OWASP floor (min 12, max ≥64) with comfortable headroom for
  passphrases, and is cheap because of pre-hashing (ADR 0007). The domain's
  `PasswordPolicy.maxLength` is to be set to 128 when the policy is wired; its
  rune cap is a DoS/UX bound only, never a hasher guard.
- **Allow all Unicode**, including multibyte characters and emoji. NIST says
  accept all Unicode; blocking it harms non-Latin users, and emoji add entropy.
- **NFC-normalize on both sides** — before hashing *and* before length-counting.
  An NFC-vs-NFD mismatch (`é` as U+00E9 vs `e`+U+0301) yields different bytes,
  hence a different hash, hence a silent login failure.
- **Count code points, never bytes,** everywhere user-facing. JS:
  `[...pw.normalize('NFC')].length`, not `pw.length` (UTF-16 units miscount
  emoji). HTML `maxlength` is a coarse UTF-16 guard only.
- **API byte cap** for the password field: at least `128 * 4 = 512 B`; use
  **1 KB** headroom so the byte cap can never bite before the rune cap, with an
  HTTP body cap (~1 MB) as a separate backstop.
- **Check order, cheap→expensive:** byte cap → rune count + char-class rules →
  pre-hash + hash.

We will **not** trim the password, block paste, restrict to ASCII, normalize on
only one side, or count length before normalization.

## Consequences

- "128 characters" means the same for ASCII and emoji; no bytes-intuition leaks
  into the UI.
- Normalization must be applied consistently in the front-end, app, and hashing
  adapter; a single missed spot reintroduces silent login failures.
- The domain's current `Validate` counts the raw string without normalizing
  (`password_policy.go`); either normalize there or document that callers must
  pass NFC plaintext.
