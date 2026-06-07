package domain

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// VerificationToken errors.
var (
	ErrInvalidVerificationTokenID = errors.New("domain: invalid verification token id")
	ErrInvalidPurpose             = errors.New("domain: invalid verification purpose")
	ErrTokenExpired               = errors.New("domain: verification token expired")
	ErrTokenConsumed              = errors.New("domain: verification token already consumed")
)

// ---------------------------------------------------------------------------
// VerificationTokenID
// ---------------------------------------------------------------------------

// VerificationTokenID is the opaque identity of a verification token record
// (not the secret the user presents).
type VerificationTokenID uuid.UUID

func NewVerificationTokenID() VerificationTokenID { return VerificationTokenID(uuid.New()) }

func ParseVerificationTokenID(s string) (VerificationTokenID, error) {
	id, err := uuid.Parse(strings.TrimSpace(s))
	if err != nil {
		return VerificationTokenID{}, fmt.Errorf("%w: %q", ErrInvalidVerificationTokenID, s)
	}
	return VerificationTokenID(id), nil
}

func (id VerificationTokenID) String() string { return uuid.UUID(id).String() }
func (id VerificationTokenID) IsZero() bool   { return uuid.UUID(id) == uuid.Nil }

// ---------------------------------------------------------------------------
// Purpose
// ---------------------------------------------------------------------------

// Purpose discriminates what a verification token authorises. A token is bound
// to exactly one purpose and may never be consumed for another, so a password
// reset link can never be replayed to verify an email. The zero value is
// invalid.
type Purpose uint8

const (
	// PurposeEmailVerify confirms ownership of an email at registration.
	PurposeEmailVerify Purpose = iota + 1
	// PurposePasswordReset authorises a single password change ("forgot password").
	PurposePasswordReset
	// PurposeMagicLink grants a passwordless login.
	PurposeMagicLink
	// PurposePhoneVerify confirms ownership of a phone number (SMS code).
	PurposePhoneVerify
)

func (p Purpose) String() string {
	switch p {
	case PurposeEmailVerify:
		return "email_verify"
	case PurposePasswordReset:
		return "password_reset"
	case PurposeMagicLink:
		return "magic_link"
	case PurposePhoneVerify:
		return "phone_verify"
	default:
		return "unknown"
	}
}

// Valid reports whether p is a defined purpose.
func (p Purpose) Valid() bool { return p >= PurposeEmailVerify && p <= PurposePhoneVerify }

// ttlByPurpose is the domain's lifetime policy per purpose. Shorter windows for
// stronger side-channels / higher-risk actions: a magic link logs you in, so it
// is short-lived; an email-verify link is a low-risk confirmation, so it lives
// longer.
var ttlByPurpose = map[Purpose]time.Duration{
	PurposeEmailVerify:   24 * time.Hour,
	PurposePasswordReset: 1 * time.Hour,
	PurposeMagicLink:     15 * time.Minute,
	PurposePhoneVerify:   10 * time.Minute,
}

// TTL returns the configured lifetime for the purpose. The ok result is false
// for any purpose without a policy entry, making ttlByPurpose the single source
// of truth: a new Purpose constant added without a TTL fails loudly here rather
// than silently minting a zero-TTL (instantly expired) token.
func (p Purpose) TTL() (time.Duration, bool) {
	ttl, ok := ttlByPurpose[p]
	return ttl, ok
}

// ---------------------------------------------------------------------------
// VerificationToken (aggregate root)
// ---------------------------------------------------------------------------

// VerificationToken is the proof-of-possession challenge behind email
// verification, password reset, magic-link login, and phone verification. The
// server issues a secret, delivers it over a side channel (email/SMS), and the
// user returns it to prove control of that channel.
//
// Only the hash of the secret is stored (see TokenHash): the raw secret is
// shown/sent once and never persisted, so a store leak does not expose usable
// tokens. The aggregate enforces single-use and time-bounded consumption; it
// references its owning User by ID only, never embedding the User aggregate.
//
// TODO: "at most one active token per (userID, purpose)" is not a domain
// invariant here — a single VerificationToken cannot see its siblings. Enforce
// it in the repository/application layer (e.g. invalidate prior tokens on
// issue, or a unique partial index on unconsumed rows).
type VerificationToken struct {
	id         VerificationTokenID
	userID     UserID
	purpose    Purpose
	tokenHash  TokenHash
	createdAt  time.Time
	expiresAt  time.Time
	consumedAt *time.Time // nil = not yet consumed
}

// NewVerificationToken issues a fresh, unconsumed token. The expiry is derived
// from the domain's per-purpose TTL policy, not supplied by the caller.
func NewVerificationToken(now time.Time, userID UserID, purpose Purpose, tokenHash TokenHash) (*VerificationToken, error) {
	if userID.IsZero() {
		return nil, ErrInvalidUserID
	}
	if tokenHash.IsZero() {
		return nil, ErrEmptyTokenHash
	}
	// TTL lookup is also the purpose validity check: an unknown purpose has no
	// policy entry, so we reject here rather than calling purpose.Valid().
	ttl, ok := purpose.TTL()
	if !ok {
		return nil, fmt.Errorf("%w: %d", ErrInvalidPurpose, purpose)
	}

	return &VerificationToken{
		id:        NewVerificationTokenID(),
		userID:    userID,
		purpose:   purpose,
		tokenHash: tokenHash,
		createdAt: now,
		expiresAt: now.Add(ttl),
	}, nil
}

// ReconstituteVerificationToken rebuilds a token from persisted state without
// running creation invariants. Repository/persistence layer only.
func ReconstituteVerificationToken(
	id VerificationTokenID,
	userID UserID,
	purpose Purpose,
	tokenHash TokenHash,
	createdAt, expiresAt time.Time,
	consumedAt *time.Time,
) *VerificationToken {
	return &VerificationToken{
		id:         id,
		userID:     userID,
		purpose:    purpose,
		tokenHash:  tokenHash,
		createdAt:  createdAt,
		expiresAt:  expiresAt,
		consumedAt: consumedAt,
	}
}

// --- getters ---------------------------------------------------------------

func (t *VerificationToken) ID() VerificationTokenID { return t.id }
func (t *VerificationToken) UserID() UserID          { return t.userID }
func (t *VerificationToken) Purpose() Purpose        { return t.purpose }
func (t *VerificationToken) TokenHash() TokenHash    { return t.tokenHash }
func (t *VerificationToken) CreatedAt() time.Time    { return t.createdAt }
func (t *VerificationToken) ExpiresAt() time.Time    { return t.expiresAt }

// ConsumedAt returns the consumption time and whether the token was consumed.
func (t *VerificationToken) ConsumedAt() (time.Time, bool) {
	if t.consumedAt == nil {
		return time.Time{}, false
	}
	return *t.consumedAt, true
}

// --- queries ---------------------------------------------------------------

// IsExpired reports whether the token has passed its deadline at now.
func (t *VerificationToken) IsExpired(now time.Time) bool { return now.After(t.expiresAt) }

// IsConsumed reports whether the token has already been used.
func (t *VerificationToken) IsConsumed() bool { return t.consumedAt != nil }

// IsValid reports whether the token may still be consumed at now: unconsumed
// and not past its deadline.
func (t *VerificationToken) IsValid(now time.Time) bool {
	return !t.IsConsumed() && !t.IsExpired(now)
}

// --- behaviour -------------------------------------------------------------

// Consume marks the token used, enforcing single-use and expiry. It must be
// called only after the caller has matched the presented secret to this token's
// hash; the domain owns the lifecycle, not the constant-time comparison (that
// crypto lives in the infrastructure layer).
func (t *VerificationToken) Consume(now time.Time) error {
	if t.IsConsumed() {
		return ErrTokenConsumed
	}
	if t.IsExpired(now) {
		return ErrTokenExpired
	}
	t.consumedAt = &now
	return nil
}
