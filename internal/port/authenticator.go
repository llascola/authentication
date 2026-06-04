// Package port declares the driven ports (interfaces) the application depends
// on but does not implement. Infrastructure adapters satisfy them at wiring
// time. Keeping these out of internal/domain keeps the domain free of
// I/O-smelling contracts (e.g. context) while still inverting the dependency:
// port imports domain, never the reverse.
package port

import (
	"context"

	"authentication/internal/domain"
)

// Authenticator verifies a presented secret against a stored credential of one
// kind. Implementations live in the infrastructure layer — they own the crypto
// (bcrypt compare, TOTP validation, OAuth token exchange). Select an
// implementation by domain.Credential.Type().
type Authenticator interface {
	// Type reports which credential kind this authenticator handles.
	Type() domain.CredentialType
	// Verify returns nil when presented proves ownership of cred, else an error.
	Verify(ctx context.Context, cred domain.Credential, presented []byte) error
}
