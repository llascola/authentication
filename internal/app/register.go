package app

import (
	"context"
	"errors"

	"authentication/internal/domain"
	"authentication/internal/port"
)

// RegisterService creates a pending identity with a password credential and
// starts email verification.
type RegisterService struct {
	users    port.UserRepository
	creds    port.PasswordCredentialRepository
	tokens   port.VerificationTokenRepository
	mailer   port.Mailer
	tokenGen port.TokenGenerator
	clock    port.Clock
	pipeline passwordPipeline
}

// NewRegisterService wires the dependencies Register needs.
func NewRegisterService(
	users port.UserRepository,
	creds port.PasswordCredentialRepository,
	tokens port.VerificationTokenRepository,
	mailer port.Mailer,
	tokenGen port.TokenGenerator,
	clock port.Clock,
	normalizer port.Normalizer,
	policy domain.PasswordPolicy,
	screener port.PasswordScreener,
	hasher port.PasswordHasher,
) *RegisterService {
	return &RegisterService{
		users:    users,
		creds:    creds,
		tokens:   tokens,
		mailer:   mailer,
		tokenGen: tokenGen,
		clock:    clock,
		pipeline: passwordPipeline{normalizer, policy, screener, hasher},
	}
}

// Register validates the email and password, creates the User + PasswordCredential,
// and issues + mails an email-verification token.
//
// Enumeration safety: a duplicate email returns nil — the same outward result as
// a fresh registration — and issues no token or mail, so a caller cannot probe
// which addresses are registered. The expensive hash is computed before the
// uniqueness check, so the duplicate path does comparable work. Input-quality
// errors (malformed email, weak/breached password) are returned as-is: they
// describe the submitted values, not whether the account exists.
//
// Atomicity (ADR 0009): the User is created first. A duplicate email fails there,
// before any credential exists, so there is nothing to roll back. The credential
// create that follows targets a freshly minted UserID with no existing
// credential, so it cannot conflict — the pair lands together or not at all.
func (s *RegisterService) Register(ctx context.Context, rawEmail, plaintext string) error {
	now := s.clock.Now()

	email, err := domain.NewEmail(rawEmail)
	if err != nil {
		return err
	}
	ph, err := s.pipeline.process(ctx, plaintext)
	if err != nil {
		return err
	}

	user, err := domain.NewUser(now, email)
	if err != nil {
		return err
	}
	if err := s.users.Create(ctx, user); err != nil {
		if errors.Is(err, port.ErrEmailTaken) {
			return nil // enumeration-safe: do not reveal the address is taken
		}
		return err
	}

	cred, err := domain.NewPasswordCredential(now, user.ID(), ph)
	if err != nil {
		return err
	}
	if err := s.creds.Create(ctx, cred); err != nil {
		return err
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
