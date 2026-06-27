package app

import (
	"context"

	"authentication/internal/domain"
	"authentication/internal/port"
)

// ValidateSessionService turns a presented session token into an authenticated
// identity and slides the idle window.
type ValidateSessionService struct {
	sessions port.SessionRepository
	tokenGen port.TokenGenerator
	clock    port.Clock
}

// NewValidateSessionService wires the dependencies ValidateSession needs.
func NewValidateSessionService(
	sessions port.SessionRepository,
	tokenGen port.TokenGenerator,
	clock port.Clock,
) *ValidateSessionService {
	return &ValidateSessionService{sessions: sessions, tokenGen: tokenGen, clock: clock}
}

// Identity is the authenticated result of a valid session: who the caller is and
// the assurance level the session reached. Roles are read live from the User
// elsewhere, never snapshotted here (see session.go).
type Identity struct {
	UserID    domain.UserID
	AuthLevel domain.AuthLevel
}

// Validate hashes the presented token, looks up the session, checks it is
// active, and touches it (sliding the idle expiry). Unknown, revoked, or expired
// sessions all return ErrNotAuthenticated. The session is written on every call,
// recording last-seen — simplest and correct for the slice.
func (s *ValidateSessionService) Validate(ctx context.Context, rawToken string) (Identity, error) {
	now := s.clock.Now()

	hash, err := s.tokenGen.Hash(rawToken)
	if err != nil {
		return Identity{}, ErrNotAuthenticated
	}
	sess, err := s.sessions.FindByTokenHash(ctx, hash)
	if err != nil {
		return Identity{}, ErrNotAuthenticated
	}
	if !sess.IsActive(now) {
		return Identity{}, ErrNotAuthenticated
	}
	if err := sess.Touch(now); err != nil {
		return Identity{}, ErrNotAuthenticated
	}
	if err := s.sessions.Update(ctx, sess); err != nil {
		return Identity{}, err
	}
	return Identity{UserID: sess.UserID(), AuthLevel: sess.AuthLevel()}, nil
}
