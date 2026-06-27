package crypto

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"

	"authentication/internal/domain"
	"authentication/internal/port"
)

var _ port.TokenGenerator = TokenGen{}

// tokenEntropyBytes is the size of the random secret drawn per token. 32 bytes
// (256 bits) is well past any practical brute-force or birthday-collision risk.
const tokenEntropyBytes = 32

// TokenGen mints opaque secrets for both session bearer tokens and verification
// tokens. It draws from crypto/rand and stores only a SHA-256 hash of the
// base64 secret string.
type TokenGen struct{}

// Generate returns a fresh GeneratedToken: a base64url raw secret and the
// SHA-256 hash of that raw string. The hash is taken over the base64 string
// (not the underlying random bytes) so that validate-session can re-hash the
// cookie value it receives the same way (T15). A crypto/rand failure is a fatal
// entropy fault and is propagated, never masked.
func (TokenGen) Generate(_ context.Context) (port.GeneratedToken, error) {
	var b [tokenEntropyBytes]byte
	if _, err := rand.Read(b[:]); err != nil {
		return port.GeneratedToken{}, err
	}
	raw := base64.RawURLEncoding.EncodeToString(b[:])
	sum := sha256.Sum256([]byte(raw))
	h, err := domain.NewTokenHash(sum[:])
	if err != nil {
		return port.GeneratedToken{}, err
	}
	return port.GeneratedToken{Raw: raw, Hash: h}, nil
}
