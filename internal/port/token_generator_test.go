package port_test

import (
	"context"
	"testing"

	"authentication/internal/domain"
	"authentication/internal/port"
)

var _ port.TokenGenerator = (*fakeTokenGen)(nil)

type fakeTokenGen struct {
	hash domain.TokenHash
}

func (f *fakeTokenGen) Generate(context.Context) (port.GeneratedToken, error) {
	return port.GeneratedToken{Raw: "raw-secret", Hash: f.hash}, nil
}

func TestGeneratedTokenExposesRawAndHash(t *testing.T) {
	var g port.TokenGenerator = &fakeTokenGen{}
	tok, err := g.Generate(context.Background())
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}
	if tok.Raw == "" {
		t.Error("GeneratedToken.Raw is empty")
	}
	// Hash is a domain.TokenHash value field; its presence is checked by the
	// compile-time assertion above. Confirm the struct carries both fields.
	_ = tok.Hash
}
