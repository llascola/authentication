package port

import (
	"context"

	"authentication/internal/domain"
)

// Mailer delivers a raw verification or reset secret over a side channel
// (email). It stays delivery-agnostic: one method per purpose keeps call sites
// explicit, rather than a generic Send(template, ...). Magic-link and
// phone-verify purposes exist in the domain but are out of the password slice's
// scope.
//
// rawToken is secret. Real implementations MUST NOT log or persist it. The
// slice's stub adapter (T09) logs it for local dev only — a deliberate
// exception, never for production.
type Mailer interface {
	SendEmailVerification(ctx context.Context, to domain.Email, rawToken string) error
	SendPasswordReset(ctx context.Context, to domain.Email, rawToken string) error
}
