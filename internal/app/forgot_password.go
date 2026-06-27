package app

import (
	"context"

	"authentication/internal/domain"
	"authentication/internal/port"
)

// ForgotPasswordService starts the reset flow: mint a reset token and mail it,
// revealing nothing about whether the email is registered.
type ForgotPasswordService struct {
	users    port.UserRepository
	tokens   port.VerificationTokenRepository
	mailer   port.Mailer
	tokenGen port.TokenGenerator
	clock    port.Clock
}

// NewForgotPasswordService wires the dependencies ForgotPassword needs.
func NewForgotPasswordService(
	users port.UserRepository,
	tokens port.VerificationTokenRepository,
	mailer port.Mailer,
	tokenGen port.TokenGenerator,
	clock port.Clock,
) *ForgotPasswordService {
	return &ForgotPasswordService{users: users, tokens: tokens, mailer: mailer, tokenGen: tokenGen, clock: clock}
}

// ForgotPassword issues a password-reset token and mails it — but only for a
// registered address. An unknown or malformed email returns nil all the same,
// issuing nothing: the outward result is identical, so a caller cannot probe
// which addresses exist. Creating the token invalidates any prior unconsumed
// reset token for the user (ADR 0009, enforced by the repository).
func (s *ForgotPasswordService) ForgotPassword(ctx context.Context, rawEmail string) error {
	now := s.clock.Now()

	email, err := domain.NewEmail(rawEmail)
	if err != nil {
		return nil // malformed: no leak, nothing issued
	}
	user, err := s.users.FindByEmail(ctx, email)
	if err != nil {
		return nil // unknown account: no leak, nothing issued
	}

	gt, err := s.tokenGen.Generate(ctx)
	if err != nil {
		return err
	}
	vt, err := domain.NewVerificationToken(now, user.ID(), domain.PurposePasswordReset, gt.Hash)
	if err != nil {
		return err
	}
	if err := s.tokens.Create(ctx, vt); err != nil {
		return err
	}
	return s.mailer.SendPasswordReset(ctx, email, gt.Raw)
}
