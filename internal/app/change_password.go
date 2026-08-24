package app

import (
	"context"

	"authentication/internal/domain"
	"authentication/internal/port"
)

// ChangePasswordService performs an authenticated password change: prove the old
// password, set a new one.
type ChangePasswordService struct {
	creds         port.PasswordCredentialRepository
	sessions      port.SessionRepository
	authenticator port.Authenticator
	normalizer    port.Normalizer
	clock         port.Clock
	pipeline      passwordPipeline
}

// NewChangePasswordService wires the dependencies ChangePassword needs.
func NewChangePasswordService(
	creds port.PasswordCredentialRepository,
	sessions port.SessionRepository,
	authenticator port.Authenticator,
	normalizer port.Normalizer,
	policy domain.PasswordPolicy,
	screener port.PasswordScreener,
	hasher port.PasswordHasher,
	clock port.Clock,
) *ChangePasswordService {
	return &ChangePasswordService{
		creds:         creds,
		sessions:      sessions,
		authenticator: authenticator,
		normalizer:    normalizer,
		clock:         clock,
		pipeline:      passwordPipeline{normalizer, policy, screener, hasher},
	}
}

// ChangePassword verifies the current password, then validates, screens, hashes,
// and rotates to the new one. caller is the authenticated Identity that
// ValidateSession produced, so the use-case knows both who is acting and which
// session they are acting from.
//
// A wrong current password returns ErrAuthFailed. Input-quality errors on the
// new password are returned as-is.
//
// Session policy: on success every OTHER session for the user is revoked and the
// calling one survives (ADR 0017, superseding that part of ADR 0015). Proving
// the old password from a live session is not evidence that session is
// compromised, and logging someone out of the page they just used is the kind of
// friction that trains people not to change passwords at all. Every other
// session dies, so a change still evicts an attacker holding a stolen cookie.
//
// A zero caller.SessionHash spares nothing and the call degrades to revoking
// everything — the safe direction if an unauthenticated path ever reaches here.
//
// ResetPassword deliberately keeps the all-revoking behaviour: it authenticates
// with a mailed token rather than the old password, there is no calling session
// to preserve, and the user may be recovering from a compromise.
func (s *ChangePasswordService) ChangePassword(ctx context.Context, caller Identity, oldPlaintext, newPlaintext string) error {
	now := s.clock.Now()

	cred, err := s.creds.FindByUserID(ctx, caller.UserID)
	if err != nil {
		return ErrAuthFailed
	}
	if err := s.authenticator.Verify(ctx, cred, []byte(s.normalizer.Normalize(oldPlaintext))); err != nil {
		return ErrAuthFailed
	}

	ph, err := s.pipeline.process(ctx, newPlaintext)
	if err != nil {
		return err
	}
	if err := cred.Rotate(now, ph); err != nil {
		return err
	}
	if err := s.creds.Update(ctx, cred); err != nil {
		return err
	}
	return s.sessions.RevokeAllExcept(ctx, caller.UserID, caller.SessionHash, now, "password changed")
}
