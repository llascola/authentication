package port

import (
	"context"

	"authentication/internal/domain"
)

// GeneratedToken is the result of minting an opaque secret: the Raw secret to
// deliver once (to a client as a session bearer token, or over a side channel
// as a verification secret) and the Hash to persist. Raw is secret — it must
// never be logged or stored; only Hash is written to a repository (see
// session.go, verification.go).
type GeneratedToken struct {
	Raw  string           // delivered once; never logged or persisted
	Hash domain.TokenHash // persisted in place of the raw secret
}

// TokenGenerator mints a high-entropy opaque secret and its stored hash, and
// re-derives that hash from a presented raw secret. One generator serves both
// session bearer tokens and verification-token secrets — they share the same
// entropy needs. The adapter (T08) draws from crypto/rand and owns the hash
// algorithm; the port is silent on it.
type TokenGenerator interface {
	// Generate returns a fresh secret and its persisted hash.
	Generate(ctx context.Context) (GeneratedToken, error)
	// Hash re-derives the stored TokenHash from a raw secret a client presented
	// (a session cookie or a verification link token). It MUST use the exact
	// recipe Generate used, so a lookup by hash matches. This is what lets the
	// application validate a presented token without the generator leaking its
	// algorithm. The raw secret is never logged or persisted.
	Hash(raw string) (domain.TokenHash, error)
}
