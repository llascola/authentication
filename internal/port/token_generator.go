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

// TokenGenerator mints a high-entropy opaque secret and its stored hash in one
// call. One generator serves both session bearer tokens and verification-token
// secrets — they share the same entropy needs. The adapter (T08) draws from
// crypto/rand and chooses the hash algorithm; the port is silent on both.
type TokenGenerator interface {
	Generate(ctx context.Context) (GeneratedToken, error)
}
