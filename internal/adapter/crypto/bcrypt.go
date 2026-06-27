// Package crypto holds the infrastructure crypto adapters: password hashing +
// verification (bcrypt) and opaque token generation. The domain owns no crypto;
// it lives here behind the port interfaces.
package crypto

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/bcrypt"

	"authentication/internal/domain"
	"authentication/internal/port"
)

// ErrPasswordMismatch reports that a presented password did not match the
// stored hash. It is deliberately a single, generic error: callers (T14) map it
// to the same response as "user not found" so the API stays enumeration-safe.
var ErrPasswordMismatch = errors.New("crypto: password mismatch")

// errWrongCredentialType is a programming error: Verify was handed a credential
// that is not a *domain.PasswordCredential. It is distinct from a mismatch
// because it signals a wiring bug, not a failed login.
var errWrongCredentialType = errors.New("crypto: authenticator received non-password credential")

var (
	_ port.PasswordHasher = Bcrypt{}
	_ port.Authenticator  = Bcrypt{}
)

// Bcrypt implements both sides of password crypto over bcrypt with a SHA-256
// prehash (ADR 0007). It assumes its input is already NFC-normalized — that is
// the application's job (ADR 0006), not this adapter's.
type Bcrypt struct {
	cost int
}

// NewBcrypt builds a Bcrypt at the given cost. A cost outside bcrypt's accepted
// range falls back to bcrypt.DefaultCost.
func NewBcrypt(cost int) Bcrypt {
	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		cost = bcrypt.DefaultCost
	}
	return Bcrypt{cost: cost}
}

// prehash maps an arbitrary-length password to a fixed 44-byte base64 string,
// defeating bcrypt's 72-byte input truncation without discarding entropy: every
// bit of the password feeds the SHA-256 digest (ADR 0007).
func prehash(plaintext string) []byte {
	sum := sha256.Sum256([]byte(plaintext))
	b64 := base64.StdEncoding.EncodeToString(sum[:]) // 44 bytes, < 72
	return []byte(b64)
}

// Hash returns the bcrypt-encoded hash of an NFC-normalized plaintext. The
// result is opaque; the app wraps it with domain.NewPasswordHash for storage.
func (b Bcrypt) Hash(_ context.Context, plaintext string) ([]byte, error) {
	return bcrypt.GenerateFromPassword(prehash(plaintext), b.cost)
}

// Type reports that this authenticator handles password credentials.
func (Bcrypt) Type() domain.CredentialType { return domain.CredentialPassword }

// Verify returns nil when presented matches the stored password hash, else
// ErrPasswordMismatch. The comparison is constant-time via
// bcrypt.CompareHashAndPassword. cred must be a *domain.PasswordCredential.
func (Bcrypt) Verify(_ context.Context, cred domain.Credential, presented []byte) error {
	pc, ok := cred.(*domain.PasswordCredential)
	if !ok {
		return errWrongCredentialType
	}
	err := bcrypt.CompareHashAndPassword(pc.Hash().Bytes(), prehash(string(presented)))
	if err != nil {
		return ErrPasswordMismatch
	}
	return nil
}
