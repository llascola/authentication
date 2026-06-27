package app

import (
	"context"

	"authentication/internal/port"
)

// LogoutService revokes the session behind a presented token.
type LogoutService struct {
	sessions port.SessionRepository
	tokenGen port.TokenGenerator
	clock    port.Clock
}

// NewLogoutService wires the dependencies Logout needs.
func NewLogoutService(
	sessions port.SessionRepository,
	tokenGen port.TokenGenerator,
	clock port.Clock,
) *LogoutService {
	return &LogoutService{sessions: sessions, tokenGen: tokenGen, clock: clock}
}

// Logout revokes the session for the presented token. It is idempotent: a
// malformed token, an unknown session, or an already-revoked session all return
// nil — the client ends up logged out either way, and the HTTP layer clears the
// cookie regardless.
func (s *LogoutService) Logout(ctx context.Context, rawToken string) error {
	now := s.clock.Now()

	hash, err := s.tokenGen.Hash(rawToken)
	if err != nil {
		return nil // malformed token: already not a session
	}
	sess, err := s.sessions.FindByTokenHash(ctx, hash)
	if err != nil {
		return nil // unknown: already gone
	}
	if err := sess.Revoke(now, "user logout"); err != nil {
		return nil // already revoked/expired: nothing to do
	}
	return s.sessions.Update(ctx, sess)
}
