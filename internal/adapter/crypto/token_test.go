package crypto_test

import (
	"crypto/sha256"
	"testing"

	"authentication/internal/adapter/crypto"
	"authentication/internal/domain"
)

func TestGenerateProducesUniqueTokens(t *testing.T) {
	g := crypto.TokenGen{}
	seenRaw := map[string]bool{}
	seenHash := map[string]bool{}
	for i := range 100 {
		tok, err := g.Generate(ctx)
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		if tok.Raw == "" {
			t.Fatal("empty Raw")
		}
		if seenRaw[tok.Raw] {
			t.Fatalf("duplicate Raw at iter %d", i)
		}
		hk := string(tok.Hash.Bytes())
		if seenHash[hk] {
			t.Fatalf("duplicate Hash at iter %d", i)
		}
		seenRaw[tok.Raw] = true
		seenHash[hk] = true
	}
}

func TestGenerateHashIsSHA256OfRaw(t *testing.T) {
	g := crypto.TokenGen{}
	tok, err := g.Generate(ctx)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	// Re-hashing the raw string the way validate-session would must reproduce
	// the stored hash.
	sum := sha256.Sum256([]byte(tok.Raw))
	want, err := domain.NewTokenHash(sum[:])
	if err != nil {
		t.Fatalf("NewTokenHash: %v", err)
	}
	if !tok.Hash.Equal(want) {
		t.Error("stored Hash is not SHA-256 of Raw")
	}
}
