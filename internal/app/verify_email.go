package app

import (
	"context"
	"errors"

	"authentication/internal/domain"
	"authentication/internal/port"
)

// VerifyEmailService consumes an email-verification token and promotes the
// pending user to active.
type VerifyEmailService struct {
	users    port.UserRepository
	tokens   port.VerificationTokenRepository
	tokenGen port.TokenGenerator
	clock    port.Clock
}

// NewVerifyEmailService wires the dependencies VerifyEmail needs.
func NewVerifyEmailService(
	users port.UserRepository,
	tokens port.VerificationTokenRepository,
	tokenGen port.TokenGenerator,
	clock port.Clock,
) *VerifyEmailService {
	return &VerifyEmailService{users: users, tokens: tokens, tokenGen: tokenGen, clock: clock}
}

// VerifyEmail matches the presented raw token by hash, consumes it (single-use +
// expiry enforced in the domain), and marks the user's email verified — which
// promotes a pending account to active.
//
// The token is consumed before the user is mutated, so a replayed token cannot
// re-verify. Unknown, expired, already-consumed, or wrong-purpose tokens all
// collapse to ErrInvalidToken. An already-verified email is treated as
// idempotent success.
func (s *VerifyEmailService) VerifyEmail(ctx context.Context, rawToken string) error {
	now := s.clock.Now()

	hash, err := s.tokenGen.Hash(rawToken)
	if err != nil {
		return ErrInvalidToken
	}
	vt, err := s.tokens.FindByTokenHash(ctx, hash)
	if err != nil {
		return ErrInvalidToken
	}
	if vt.Purpose() != domain.PurposeEmailVerify {
		return ErrInvalidToken
	}
	if err := vt.Consume(now); err != nil {
		return ErrInvalidToken
	}
	if err := s.tokens.Update(ctx, vt); err != nil {
		return err
	}

	user, err := s.users.FindByID(ctx, vt.UserID())
	if err != nil {
		return err
	}
	if err := user.VerifyEmail(now); err != nil {
		if errors.Is(err, domain.ErrEmailAlreadyVerified) {
			return nil // idempotent
		}
		return err
	}
	return s.users.Update(ctx, user)
}
