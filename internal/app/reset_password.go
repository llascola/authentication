package app

import (
	"context"

	"authentication/internal/domain"
	"authentication/internal/port"
)

// ResetPasswordService finishes the reset flow: consume the token, set a new
// password, and kill every session.
type ResetPasswordService struct {
	creds    port.PasswordCredentialRepository
	sessions port.SessionRepository
	tokens   port.VerificationTokenRepository
	tokenGen port.TokenGenerator
	clock    port.Clock
	pipeline passwordPipeline
}

// NewResetPasswordService wires the dependencies ResetPassword needs.
func NewResetPasswordService(
	creds port.PasswordCredentialRepository,
	sessions port.SessionRepository,
	tokens port.VerificationTokenRepository,
	tokenGen port.TokenGenerator,
	normalizer port.Normalizer,
	policy domain.PasswordPolicy,
	screener port.PasswordScreener,
	hasher port.PasswordHasher,
	clock port.Clock,
) *ResetPasswordService {
	return &ResetPasswordService{
		creds:    creds,
		sessions: sessions,
		tokens:   tokens,
		tokenGen: tokenGen,
		clock:    clock,
		pipeline: passwordPipeline{normalizer, policy, screener, hasher},
	}
}

// ResetPassword consumes a reset token, rotates the password, and revokes every
// session for the user. The new password is validated and hashed BEFORE the
// token is consumed, so a rejected password (too weak, breached) leaves the
// token spendable and the user can retry on the same link — only a successful
// rotation burns it. Consumption still precedes the rotation, so a replay cannot
// reset twice. Unknown, expired, consumed, or wrong-purpose tokens return
// ErrInvalidToken. Unlike ChangePassword, no session is exempt — a reset implies
// possible compromise.
func (s *ResetPasswordService) ResetPassword(ctx context.Context, rawToken, newPlaintext string) error {
	now := s.clock.Now()

	hash, err := s.tokenGen.Hash(rawToken)
	if err != nil {
		return ErrInvalidToken
	}
	vt, err := s.tokens.FindByTokenHash(ctx, hash)
	if err != nil {
		return ErrInvalidToken
	}
	if vt.Purpose() != domain.PurposePasswordReset {
		return ErrInvalidToken
	}
	if !vt.IsValid(now) {
		return ErrInvalidToken // expired or already consumed — fail before hashing
	}

	// Validate and hash the new password before consuming the token: an
	// input-quality rejection must not burn a still-good reset link.
	ph, err := s.pipeline.process(ctx, newPlaintext)
	if err != nil {
		return err
	}

	if err := vt.Consume(now); err != nil {
		return ErrInvalidToken
	}
	if err := s.tokens.Update(ctx, vt); err != nil {
		return err
	}

	cred, err := s.creds.FindByUserID(ctx, vt.UserID())
	if err != nil {
		return err
	}
	if err := cred.Rotate(now, ph); err != nil {
		return err
	}
	if err := s.creds.Update(ctx, cred); err != nil {
		return err
	}
	return s.sessions.RevokeAllForUser(ctx, vt.UserID(), now, "password reset")
}
