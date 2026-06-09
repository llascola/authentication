# 0007. Password hashing: pre-hash bcrypt or use argon2id

- Status: Accepted
- Date: 2026-06-06

## Context

Raw bcrypt silently truncates input at **72 bytes**. That is 72 ASCII chars but
only ~36 `é`, ~24 CJK, or **18 emoji**. With the 128-rune cap from ADR 0006,
raw bcrypt would drop most of a multibyte password and the "128 characters"
promise becomes a lie. The domain is hasher-agnostic — `PasswordHash` only
stores a non-empty precomputed hash — so this is an infrastructure decision.

## Decision

If we use bcrypt, we will **pre-hash the password to a fixed size first**:

```go
sum := sha256.Sum256([]byte(nfcNormalizedPassword)) // always 32 bytes
b64 := base64.StdEncoding.EncodeToString(sum[:])      // always 44 ASCII bytes
hash, _ := bcrypt.GenerateFromPassword([]byte(b64), cost)
```

bcrypt then always sees 44 bytes, so the 72-byte limit is never reached and the
full password contributes. **base64 is required** (not the raw digest): a raw
SHA-256 digest can contain a NUL byte, and bcrypt is C-string based and would
truncate at the first `0x00`.

**Preferred for greenfield: argon2id.** It has no 72-byte limit, needs no
pre-hash dance, and is the modern OWASP first choice. Where we are free to
choose, use argon2id over bcrypt.

| Approach | 128-char multibyte safe? |
|---|---|
| Raw bcrypt | NO (≈18 emoji) |
| Pre-hash → bcrypt | yes |
| argon2id / scrypt | yes (native) |

Hashing runs in the infra adapter, **after** NFC normalization and length checks
(ADR 0006). Algorithm metadata is not stored in the domain: bcrypt/argon2 hashes
are self-describing, so rehash-on-login (`NeedsRehash`) belongs on a future
`PasswordHasher` port that parses the `$`-prefixed string; the domain already
exposes `PasswordCredential.Rotate(now, newHash)` for the swap.

## Consequences

- The 128-rune promise holds regardless of character width.
- Choosing bcrypt commits us to the pre-hash recipe everywhere a password is
  hashed or verified — applied inconsistently, it silently breaks login.
- argon2id avoids the recipe entirely and is the recommended path.
- No `HashAlgo` value object in the domain (it would duplicate bytes and risk
  drift); rehash detection is an infra/port concern.
