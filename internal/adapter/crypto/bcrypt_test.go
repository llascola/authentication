package crypto_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"authentication/internal/adapter/crypto"
	"authentication/internal/domain"
)

var ctx = context.Background()

// lowCost keeps the bcrypt work factor small so tests stay fast; NewBcrypt
// clamps below MinCost up to DefaultCost, so use MinCost explicitly.
func lowCost(t *testing.T) crypto.Bcrypt {
	t.Helper()
	return crypto.NewBcrypt(4) // bcrypt.MinCost
}

func mustCredential(t *testing.T, hash []byte) *domain.PasswordCredential {
	t.Helper()
	ph, err := domain.NewPasswordHash(hash)
	if err != nil {
		t.Fatalf("NewPasswordHash: %v", err)
	}
	c, err := domain.NewPasswordCredential(time.Now(), domain.NewUserID(), ph)
	if err != nil {
		t.Fatalf("NewPasswordCredential: %v", err)
	}
	return c
}

func TestHashVerifyRoundTrip(t *testing.T) {
	b := lowCost(t)
	hash, err := b.Hash(ctx, "correct horse battery staple")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	cred := mustCredential(t, hash)
	if err := b.Verify(ctx, cred, []byte("correct horse battery staple")); err != nil {
		t.Errorf("Verify on correct password = %v, want nil", err)
	}
}

func TestVerifyWrongPasswordRejected(t *testing.T) {
	b := lowCost(t)
	hash, err := b.Hash(ctx, "right-password")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	cred := mustCredential(t, hash)
	err = b.Verify(ctx, cred, []byte("wrong-password"))
	if !errors.Is(err, crypto.ErrPasswordMismatch) {
		t.Errorf("Verify on wrong password = %v, want ErrPasswordMismatch", err)
	}
}

func TestHashIsSaltedDifferentEachCall(t *testing.T) {
	b := lowCost(t)
	h1, err := b.Hash(ctx, "same-password")
	if err != nil {
		t.Fatalf("Hash 1: %v", err)
	}
	h2, err := b.Hash(ctx, "same-password")
	if err != nil {
		t.Fatalf("Hash 2: %v", err)
	}
	if bytes.Equal(h1, h2) {
		t.Error("two hashes of the same password are identical; salt missing")
	}
}

func TestPrehashAllowsPasswordsOver72Bytes(t *testing.T) {
	b := lowCost(t)
	// Two distinct passwords that share the first 72 bytes. Without the SHA-256
	// prehash, bcrypt would truncate at 72 and treat them as equal.
	base := strings.Repeat("a", 72)
	pwA := base + "AAAA"
	pwB := base + "BBBB"

	hash, err := b.Hash(ctx, pwA)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	cred := mustCredential(t, hash)

	if err := b.Verify(ctx, cred, []byte(pwA)); err != nil {
		t.Errorf("Verify pwA = %v, want nil", err)
	}
	if err := b.Verify(ctx, cred, []byte(pwB)); !errors.Is(err, crypto.ErrPasswordMismatch) {
		t.Errorf("Verify pwB (differs past byte 72) = %v, want ErrPasswordMismatch", err)
	}
}
