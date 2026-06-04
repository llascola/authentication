package domain

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Credential errors.
var (
	ErrInvalidCredentialID = errors.New("domain: invalid credential id")
	ErrEmptyPasswordHash   = errors.New("domain: password hash is empty")
	ErrEmptyTOTPSecret     = errors.New("domain: totp secret is empty")
	ErrInvalidOTPDigits    = errors.New("domain: otp digits out of range")
	ErrInvalidProvider     = errors.New("domain: invalid oauth provider")
	ErrEmptySubject        = errors.New("domain: oauth subject is required")
	ErrUnknownCredential   = errors.New("domain: unknown credential type")
	ErrOTPAlreadyConfirmed = errors.New("domain: otp already confirmed")
)

// ---------------------------------------------------------------------------
// CredentialID
// ---------------------------------------------------------------------------

// CredentialID is the opaque identity of a single stored credential.
type CredentialID uuid.UUID

func NewCredentialID() CredentialID { return CredentialID(uuid.New()) }

func ParseCredentialID(s string) (CredentialID, error) {
	id, err := uuid.Parse(strings.TrimSpace(s))
	if err != nil {
		return CredentialID{}, fmt.Errorf("%w: %q", ErrInvalidCredentialID, s)
	}
	return CredentialID(id), nil
}

func (id CredentialID) String() string { return uuid.UUID(id).String() }
func (id CredentialID) IsZero() bool   { return uuid.UUID(id) == uuid.Nil }

// ---------------------------------------------------------------------------
// CredentialType
// ---------------------------------------------------------------------------

// CredentialType discriminates the kind of a Credential. Useful for storage
// routing and for picking the matching Authenticator.
type CredentialType string

const (
	CredentialPassword CredentialType = "password"
	CredentialOAuth    CredentialType = "oauth"
	CredentialOTP      CredentialType = "otp"
)

func (t CredentialType) Valid() bool {
	switch t {
	case CredentialPassword, CredentialOAuth, CredentialOTP:
		return true
	default:
		return false
	}
}

// ---------------------------------------------------------------------------
// Credential (sealed sum type)
// ---------------------------------------------------------------------------

// Credential is the common contract shared by every credential kind. It exposes
// only identity/metadata, never kind-specific secrets, so callers can list and
// handle a user's credentials uniformly (e.g. in a repository) without leaking
// secret material.
//
// The unexported sealed method makes this a closed set: only the concrete
// credential types declared in this package can satisfy it.
type Credential interface {
	ID() CredentialID
	UserID() UserID
	Type() CredentialType
	CreatedAt() time.Time

	sealedCredential()
}

// ---------------------------------------------------------------------------
// Value objects for secret material
// ---------------------------------------------------------------------------

// PasswordHash holds a pre-computed password hash (bcrypt/argon2/...). The
// domain never hashes or compares — that crypto lives in the infrastructure
// layer. This type only guarantees the stored hash is non-empty.
type PasswordHash struct {
	value []byte
}

// NewPasswordHash wraps an already-computed hash. Plaintext must never reach
// this constructor.
func NewPasswordHash(hash []byte) (PasswordHash, error) {
	if len(hash) == 0 {
		return PasswordHash{}, ErrEmptyPasswordHash
	}
	return PasswordHash{value: append([]byte(nil), hash...)}, nil
}

// Bytes returns a copy of the hash bytes; the internal slice is not exposed.
func (h PasswordHash) Bytes() []byte { return append([]byte(nil), h.value...) }
func (h PasswordHash) IsZero() bool  { return len(h.value) == 0 }

// TOTPSecret holds the shared secret seed for a TOTP authenticator.
type TOTPSecret struct {
	value []byte
}

func NewTOTPSecret(secret []byte) (TOTPSecret, error) {
	if len(secret) == 0 {
		return TOTPSecret{}, ErrEmptyTOTPSecret
	}
	return TOTPSecret{value: append([]byte(nil), secret...)}, nil
}

func (s TOTPSecret) Bytes() []byte { return append([]byte(nil), s.value...) }
func (s TOTPSecret) IsZero() bool  { return len(s.value) == 0 }

// Provider is a supported OAuth/OIDC identity provider.
type Provider string

const (
	ProviderGoogle Provider = "google"
	ProviderGitHub Provider = "github"
)

func (p Provider) Valid() bool {
	switch p {
	case ProviderGoogle, ProviderGitHub:
		return true
	default:
		return false
	}
}

// ---------------------------------------------------------------------------
// PasswordCredential
// ---------------------------------------------------------------------------

// PasswordCredential stores a single user's password hash.
type PasswordCredential struct {
	id        CredentialID
	userID    UserID
	hash      PasswordHash
	createdAt time.Time
	updatedAt time.Time
}

func NewPasswordCredential(userID UserID, hash PasswordHash) (*PasswordCredential, error) {
	if userID.IsZero() {
		return nil, ErrInvalidUserID
	}
	if hash.IsZero() {
		return nil, ErrEmptyPasswordHash
	}
	now := time.Now().UTC()
	return &PasswordCredential{
		id:        NewCredentialID(),
		userID:    userID,
		hash:      hash,
		createdAt: now,
		updatedAt: now,
	}, nil
}

func (c *PasswordCredential) ID() CredentialID     { return c.id }
func (c *PasswordCredential) UserID() UserID       { return c.userID }
func (c *PasswordCredential) Type() CredentialType { return CredentialPassword }
func (c *PasswordCredential) CreatedAt() time.Time { return c.createdAt }
func (c *PasswordCredential) UpdatedAt() time.Time { return c.updatedAt }
func (c *PasswordCredential) Hash() PasswordHash   { return c.hash }
func (c *PasswordCredential) sealedCredential()    {}

// Rotate replaces the stored hash (e.g. on password change or rehash).
func (c *PasswordCredential) Rotate(hash PasswordHash) error {
	if hash.IsZero() {
		return ErrEmptyPasswordHash
	}
	c.hash = hash
	c.updatedAt = time.Now().UTC()
	return nil
}

// ---------------------------------------------------------------------------
// OAuthCredential
// ---------------------------------------------------------------------------

// OAuthCredential links a user to an external identity provider account. The
// (provider, subject) pair is the stable foreign identity; no secret is stored
// here — tokens are short-lived and handled by the auth flow, not persisted as
// a credential.
type OAuthCredential struct {
	id        CredentialID
	userID    UserID
	provider  Provider
	subject   string // provider's stable user id (OIDC "sub")
	createdAt time.Time
}

func NewOAuthCredential(userID UserID, provider Provider, subject string) (*OAuthCredential, error) {
	if userID.IsZero() {
		return nil, ErrInvalidUserID
	}
	if !provider.Valid() {
		return nil, fmt.Errorf("%w: %q", ErrInvalidProvider, provider)
	}
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return nil, ErrEmptySubject
	}
	return &OAuthCredential{
		id:        NewCredentialID(),
		userID:    userID,
		provider:  provider,
		subject:   subject,
		createdAt: time.Now().UTC(),
	}, nil
}

func (c *OAuthCredential) ID() CredentialID     { return c.id }
func (c *OAuthCredential) UserID() UserID       { return c.userID }
func (c *OAuthCredential) Type() CredentialType { return CredentialOAuth }
func (c *OAuthCredential) CreatedAt() time.Time { return c.createdAt }
func (c *OAuthCredential) Provider() Provider   { return c.provider }
func (c *OAuthCredential) Subject() string      { return c.subject }
func (c *OAuthCredential) sealedCredential()    {}

// ---------------------------------------------------------------------------
// OTPCredential
// ---------------------------------------------------------------------------

// OTP digit bounds per RFC 6238 common usage.
const (
	minOTPDigits     = 6
	maxOTPDigits     = 8
	defaultOTPDigits = 6
)

// OTPCredential stores a TOTP shared secret for a user. It starts unconfirmed
// and is confirmed once the user proves possession by submitting a valid code.
type OTPCredential struct {
	id        CredentialID
	userID    UserID
	secret    TOTPSecret
	digits    int
	confirmed bool
	createdAt time.Time
}

// NewOTPCredential creates an unconfirmed TOTP credential. Pass digits = 0 to
// use the default (6).
func NewOTPCredential(userID UserID, secret TOTPSecret, digits int) (*OTPCredential, error) {
	if userID.IsZero() {
		return nil, ErrInvalidUserID
	}
	if secret.IsZero() {
		return nil, ErrEmptyTOTPSecret
	}
	if digits == 0 {
		digits = defaultOTPDigits
	}
	if digits < minOTPDigits || digits > maxOTPDigits {
		return nil, fmt.Errorf("%w: %d", ErrInvalidOTPDigits, digits)
	}
	return &OTPCredential{
		id:        NewCredentialID(),
		userID:    userID,
		secret:    secret,
		digits:    digits,
		createdAt: time.Now().UTC(),
	}, nil
}

func (c *OTPCredential) ID() CredentialID     { return c.id }
func (c *OTPCredential) UserID() UserID       { return c.userID }
func (c *OTPCredential) Type() CredentialType { return CredentialOTP }
func (c *OTPCredential) CreatedAt() time.Time { return c.createdAt }
func (c *OTPCredential) Secret() TOTPSecret   { return c.secret }
func (c *OTPCredential) Digits() int          { return c.digits }
func (c *OTPCredential) Confirmed() bool      { return c.confirmed }
func (c *OTPCredential) sealedCredential()    {}

// Confirm marks the credential as proven once the user submits a valid code.
func (c *OTPCredential) Confirm() error {
	if c.confirmed {
		return ErrOTPAlreadyConfirmed
	}
	c.confirmed = true
	return nil
}
