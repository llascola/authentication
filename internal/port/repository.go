package port

import (
	"context"
	"errors"
	"time"

	"authentication/internal/domain"
)

// Repository sentinel errors. Callers branch on these with errors.Is; adapters
// return them (wrapped with %w for context) instead of returning (nil, nil) on
// a miss. The not-found contract is uniform across every repository: a lookup
// that finds nothing returns the matching Err*NotFound, never a nil aggregate
// with a nil error.
var (
	// ErrUserNotFound reports that no user matched the given ID or email.
	ErrUserNotFound = errors.New("port: user not found")
	// ErrEmailTaken reports a uniqueness violation on user email (ADR 0009):
	// UserRepository.Create rejects a second user with an existing email.
	ErrEmailTaken = errors.New("port: email already registered")
	// ErrCredentialNotFound reports that no password credential exists for the
	// given user.
	ErrCredentialNotFound = errors.New("port: password credential not found")
	// ErrCredentialExists reports a uniqueness violation: a user may hold at
	// most one password credential, and one already exists for the given user.
	ErrCredentialExists = errors.New("port: password credential already exists")
	// ErrSessionNotFound reports that no session matched the given token hash.
	ErrSessionNotFound = errors.New("port: session not found")
	// ErrTokenNotFound reports that no verification token matched the given hash.
	ErrTokenNotFound = errors.New("port: verification token not found")
)

// UserRepository persists the User aggregate.
//
// Create enforces email uniqueness (ADR 0009): a second user with an
// already-registered email fails with ErrEmailTaken. Update serializes the
// read-modify-write on a single user (ADR 0008) — adapters use a row lock or an
// optimistic-version retry; the port stays silent on the mechanism. Finders
// return Err*NotFound on a miss.
type UserRepository interface {
	Create(ctx context.Context, u *domain.User) error
	Update(ctx context.Context, u *domain.User) error
	FindByID(ctx context.Context, id domain.UserID) (*domain.User, error)
	FindByEmail(ctx context.Context, email domain.Email) (*domain.User, error)
}

// PasswordCredentialRepository persists the PasswordCredential aggregate, one
// per user. Update serializes the read-modify-write (ADR 0008). FindByUserID
// returns ErrCredentialNotFound when the user has no password credential.
type PasswordCredentialRepository interface {
	Create(ctx context.Context, c *domain.PasswordCredential) error
	Update(ctx context.Context, c *domain.PasswordCredential) error
	FindByUserID(ctx context.Context, id domain.UserID) (*domain.PasswordCredential, error)
}

// SessionRepository persists the Session aggregate, keyed for lookup by the
// stored token hash (the raw bearer token is never persisted; see session.go).
//
// Update serializes session touch/revoke (ADR 0008). FindByTokenHash returns
// ErrSessionNotFound on a miss. RevokeAllForUser revokes every active session
// for a user in one serialized operation (used by password change/reset); now
// stamps the revocation instant and reason records why.
type SessionRepository interface {
	Create(ctx context.Context, s *domain.Session) error
	Update(ctx context.Context, s *domain.Session) error
	FindByTokenHash(ctx context.Context, h domain.TokenHash) (*domain.Session, error)
	RevokeAllForUser(ctx context.Context, id domain.UserID, now time.Time, reason string) error
}

// VerificationTokenRepository persists the VerificationToken aggregate.
//
// Create invalidates any prior unconsumed token for the same (userID, purpose)
// before storing the new one (ADR 0009): only the most recently minted token
// for a purpose stays valid. Update serializes consume (ADR 0008).
// FindByTokenHash returns ErrTokenNotFound on a miss.
type VerificationTokenRepository interface {
	Create(ctx context.Context, t *domain.VerificationToken) error
	Update(ctx context.Context, t *domain.VerificationToken) error
	FindByTokenHash(ctx context.Context, h domain.TokenHash) (*domain.VerificationToken, error)
}
