package domain

import (
	"errors"
	"fmt"
	"unicode"
)

// PasswordPolicy errors. Config errors come from NewPasswordPolicy; the
// Err*Password* violation errors come from Validate and are combined with
// errors.Join so a caller can report every failed rule at once and still test
// individual rules with errors.Is.
var (
	ErrInvalidPasswordPolicy = errors.New("domain: invalid password policy")

	ErrPasswordTooShort = errors.New("domain: password too short")
	ErrPasswordTooLong  = errors.New("domain: password too long")
	ErrPasswordNoUpper  = errors.New("domain: password missing uppercase letter")
	ErrPasswordNoLower  = errors.New("domain: password missing lowercase letter")
	ErrPasswordNoDigit  = errors.New("domain: password missing digit")
	ErrPasswordNoSymbol = errors.New("domain: password missing symbol")
)

// Default policy bounds.
const (
	defaultMinLength = 12
	// defaultMaxLength is a sane upper bound (rune count) to bound input and
	// avoid DoS from pathologically long passwords; it is NOT a hasher-specific
	// guard. Length here is measured in runes, so it cannot enforce a byte limit
	// such as bcrypt's 72-byte truncation. Hasher limits are an infrastructure
	// concern: the hashing adapter must own them, ideally by pre-hashing the
	// password (e.g. base64(sha256(pw)) -> bcrypt) so arbitrary-length inputs are
	// safe and no silent truncation occurs.
	defaultMaxLength = 72
)

// ---------------------------------------------------------------------------
// PasswordPolicy (value object)
// ---------------------------------------------------------------------------

// PasswordPolicy is an immutable rule set describing what counts as an
// acceptable password. It holds no per-user state and has no identity: two
// policies with the same fields are equivalent. The rule is domain logic; it is
// invoked by the application layer on the transient plaintext (which is hashed
// and discarded), so the secret never enters a domain entity.
type PasswordPolicy struct {
	minLength     int
	maxLength     int // 0 = no upper bound
	requireUpper  bool
	requireLower  bool
	requireDigit  bool
	requireSymbol bool
}

// PolicyOption customises a PasswordPolicy at construction.
type PolicyOption func(*PasswordPolicy)

// WithMinLength sets the minimum length (in characters/runes).
func WithMinLength(n int) PolicyOption { return func(p *PasswordPolicy) { p.minLength = n } }

// WithMaxLength sets the maximum length (in characters/runes); 0 disables it.
func WithMaxLength(n int) PolicyOption { return func(p *PasswordPolicy) { p.maxLength = n } }

// RequireUpper requires at least one uppercase letter.
func RequireUpper() PolicyOption { return func(p *PasswordPolicy) { p.requireUpper = true } }

// RequireLower requires at least one lowercase letter.
func RequireLower() PolicyOption { return func(p *PasswordPolicy) { p.requireLower = true } }

// RequireDigit requires at least one digit.
func RequireDigit() PolicyOption { return func(p *PasswordPolicy) { p.requireDigit = true } }

// RequireSymbol requires at least one punctuation or symbol rune.
func RequireSymbol() PolicyOption { return func(p *PasswordPolicy) { p.requireSymbol = true } }

// NewPasswordPolicy builds a policy from the default bounds plus any options,
// then validates the resulting configuration. It fails if the bounds are
// nonsensical (non-positive minimum, or a maximum below the minimum).
func NewPasswordPolicy(opts ...PolicyOption) (PasswordPolicy, error) {
	p := PasswordPolicy{
		minLength: defaultMinLength,
		maxLength: defaultMaxLength,
	}
	for _, opt := range opts {
		opt(&p)
	}

	if p.minLength <= 0 {
		return PasswordPolicy{}, fmt.Errorf("%w: min length must be positive, got %d", ErrInvalidPasswordPolicy, p.minLength)
	}
	if p.maxLength < 0 {
		return PasswordPolicy{}, fmt.Errorf("%w: max length must not be negative, got %d", ErrInvalidPasswordPolicy, p.maxLength)
	}
	if p.maxLength > 0 && p.maxLength < p.minLength {
		return PasswordPolicy{}, fmt.Errorf("%w: max length %d below min length %d", ErrInvalidPasswordPolicy, p.maxLength, p.minLength)
	}
	return p, nil
}

// DefaultPasswordPolicy returns a sensible baseline: 12-72 characters requiring
// upper, lower, and a digit (no symbol requirement). It cannot fail.
func DefaultPasswordPolicy() PasswordPolicy {
	p, _ := NewPasswordPolicy(RequireUpper(), RequireLower(), RequireDigit())
	return p
}

// --- getters ---------------------------------------------------------------

func (p PasswordPolicy) MinLength() int       { return p.minLength }
func (p PasswordPolicy) MaxLength() int       { return p.maxLength }
func (p PasswordPolicy) RequiresUpper() bool  { return p.requireUpper }
func (p PasswordPolicy) RequiresLower() bool  { return p.requireLower }
func (p PasswordPolicy) RequiresDigit() bool  { return p.requireDigit }
func (p PasswordPolicy) RequiresSymbol() bool { return p.requireSymbol }

// --- behaviour -------------------------------------------------------------

// Validate checks a candidate plaintext against the policy and returns every
// violation joined into a single error (errors.Join), or nil if it passes. Test
// individual rules with errors.Is, list all with the joined error's message.
// Length is measured in runes, so multi-byte characters count as one.
func (p PasswordPolicy) Validate(plaintext string) error {
	var hasUpper, hasLower, hasDigit, hasSymbol bool
	length := 0
	for _, r := range plaintext {
		length++
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			hasSymbol = true
		}
	}

	var errs []error
	if length < p.minLength {
		errs = append(errs, fmt.Errorf("%w: need at least %d, got %d", ErrPasswordTooShort, p.minLength, length))
	}
	if p.maxLength > 0 && length > p.maxLength {
		errs = append(errs, fmt.Errorf("%w: at most %d, got %d", ErrPasswordTooLong, p.maxLength, length))
	}
	if p.requireUpper && !hasUpper {
		errs = append(errs, ErrPasswordNoUpper)
	}
	if p.requireLower && !hasLower {
		errs = append(errs, ErrPasswordNoLower)
	}
	if p.requireDigit && !hasDigit {
		errs = append(errs, ErrPasswordNoDigit)
	}
	if p.requireSymbol && !hasSymbol {
		errs = append(errs, ErrPasswordNoSymbol)
	}

	return errors.Join(errs...)
}
