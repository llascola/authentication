package app

import (
	"context"

	"authentication/internal/domain"
	"authentication/internal/port"
)

// ResendVerificationService re-issues an email-verification token for an
// account that never completed verification.
//
// It exists because verification state is committed before the mail leaves:
// Register persists the user, credential, and token and only then calls the
// mailer. A lost, bounced, or failed send therefore strands the account in
// StatusPending with no way out — login requires StatusActive, re-registering
// is enumeration-safe and mints nothing, and a reset token is the wrong
// purpose. This is that account's only recovery path.
type ResendVerificationService struct {
	users    port.UserRepository
	tokens   port.VerificationTokenRepository
	mailer   port.Mailer
	tokenGen port.TokenGenerator
	clock    port.Clock
}

// NewResendVerificationService wires the dependencies ResendVerification needs.
func NewResendVerificationService(
	users port.UserRepository,
	tokens port.VerificationTokenRepository,
	mailer port.Mailer,
	tokenGen port.TokenGenerator,
	clock port.Clock,
) *ResendVerificationService {
	return &ResendVerificationService{users: users, tokens: tokens, mailer: mailer, tokenGen: tokenGen, clock: clock}
}

// ResendVerification issues a fresh email-verification token and mails it — but
// only for a registered address whose account is still pending and unverified.
// A malformed address, an unknown account, an already-verified email, and a
// non-pending (activated or closed) account all return nil just the same,
// issuing nothing: the outward result is identical, so a caller cannot probe
// which addresses exist or what state they are in.
//
// Creating the token invalidates any prior unconsumed verification token for
// the user (ADR 0009, enforced by the repository), so only the newest mail
// works.
//
// This is unauthenticated and mails an attacker-supplied address, so it MUST
// sit behind a rate limit before it is exposed publicly (T28); unthrottled it
// is an open mail relay aimed at the deployment's own SMTP quota.
func (s *ResendVerificationService) ResendVerification(ctx context.Context, rawEmail string) error {
	now := s.clock.Now()

	email, err := domain.NewEmail(rawEmail)
	if err != nil {
		return nil // malformed: no leak, nothing issued
	}
	user, err := s.users.FindByEmail(ctx, email)
	if err != nil {
		return nil // unknown account: no leak, nothing issued
	}
	if user.EmailVerified() {
		return nil // already verified: no leak, no mail
	}
	if user.Status() != domain.StatusPending {
		return nil // closed or otherwise past pending: nothing to verify into
	}

	gt, err := s.tokenGen.Generate(ctx)
	if err != nil {
		return err
	}
	vt, err := domain.NewVerificationToken(now, user.ID(), domain.PurposeEmailVerify, gt.Hash)
	if err != nil {
		return err
	}
	if err := s.tokens.Create(ctx, vt); err != nil {
		return err
	}
	return s.mailer.SendEmailVerification(ctx, email, gt.Raw)
}
