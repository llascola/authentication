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
// and rotates to the new one. The caller is already authenticated (T15 supplied
// userID).
//
// A wrong current password returns ErrAuthFailed. Input-quality errors on the
// new password are returned as-is.
//
// Session policy: on success, ALL of the user's sessions are revoked, including
// the one that initiated the change — a deliberately strict, secure default. The
// user must re-authenticate. (Keeping the current session alive would need a
// revoke-all-except-current repo method, out of slice scope; see T17 notes.)
func (s *ChangePasswordService) ChangePassword(ctx context.Context, userID domain.UserID, oldPlaintext, newPlaintext string) error {
	now := s.clock.Now()

	cred, err := s.creds.FindByUserID(ctx, userID)
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
	return s.sessions.RevokeAllForUser(ctx, userID, now, "password changed")
}
