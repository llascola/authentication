// Package mailer provides implementations of port.Mailer.
//
// LogMailer is a DEV-ONLY stub: it logs the raw token instead of sending an
// email, so local runs and the integration test (T23) can read the secret a
// real user would receive. A production mailer MUST NOT log the raw token —
// this exists only because the slice has no real email transport yet.
package mailer

import (
	"context"
	"log/slog"

	"authentication/internal/domain"
	"authentication/internal/port"
)

var _ port.Mailer = LogMailer{}

// LogMailer writes verification/reset deliveries to a structured logger. The
// raw token is logged as a field — DEV ONLY (see package doc). Output is
// structured so callers/tests can extract the token field.
type LogMailer struct {
	log *slog.Logger
}

// NewLogMailer builds a LogMailer over log. A nil log falls back to the slog
// default so the zero-config path still works.
func NewLogMailer(log *slog.Logger) LogMailer {
	if log == nil {
		log = slog.Default()
	}
	return LogMailer{log: log}
}

// SendEmailVerification logs the email-verification token for to. DEV ONLY.
func (m LogMailer) SendEmailVerification(_ context.Context, to domain.Email, rawToken string) error {
	m.log.Info("email verification", "to", to.String(), "token", rawToken)
	return nil
}

// SendPasswordReset logs the password-reset token for to. DEV ONLY.
func (m LogMailer) SendPasswordReset(_ context.Context, to domain.Email, rawToken string) error {
	m.log.Info("password reset", "to", to.String(), "token", rawToken)
	return nil
}
