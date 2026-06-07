package domain_test

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"authentication/internal/domain"
)

// --- helpers ---------------------------------------------------------------

func mustVerificationToken(t *testing.T, purpose domain.Purpose) *domain.VerificationToken {
	t.Helper()
	tok, err := domain.NewVerificationToken(timeFixed(), mustUserID(t), purpose, mustTokenHash(t, []byte("secret-hash")))
	if err != nil {
		t.Fatalf("NewVerificationToken: unexpected error: %v", err)
	}
	return tok
}

// reconstituteExpiredToken returns an unconsumed token whose deadline is in the
// past relative to the returned now, so time-derived expiry fires on Consume
// without controlling the wall clock.
func reconstituteExpiredToken(t *testing.T) (*domain.VerificationToken, time.Time) {
	t.Helper()
	now := timeFixed()
	past := now.Add(-2 * time.Hour)
	tok := domain.ReconstituteVerificationToken(
		domain.NewVerificationTokenID(), domain.NewUserID(),
		domain.PurposeMagicLink, mustTokenHash(t, []byte("h")),
		past, past.Add(15*time.Minute), nil,
	)
	return tok, now
}

// --- VerificationTokenID ---------------------------------------------------

func TestVerificationTokenID(t *testing.T) {
	id := domain.NewVerificationTokenID()
	if id.IsZero() {
		t.Fatal("NewVerificationTokenID returned zero id")
	}
	parsed, err := domain.ParseVerificationTokenID(id.String())
	if err != nil {
		t.Fatalf("ParseVerificationTokenID round-trip: %v", err)
	}
	if parsed != id {
		t.Errorf("round-trip = %v, want %v", parsed, id)
	}
	if _, err := domain.ParseVerificationTokenID("nope"); !errors.Is(err, domain.ErrInvalidVerificationTokenID) {
		t.Errorf("err = %v, want ErrInvalidVerificationTokenID", err)
	}
}

// --- Purpose ---------------------------------------------------------------

func TestPurpose(t *testing.T) {
	tests := []struct {
		purpose   domain.Purpose
		valid     bool
		str       string
		wantTTL   time.Duration
		wantOkTTL bool
	}{
		{domain.PurposeEmailVerify, true, "email_verify", 24 * time.Hour, true},
		{domain.PurposePasswordReset, true, "password_reset", 1 * time.Hour, true},
		{domain.PurposeMagicLink, true, "magic_link", 15 * time.Minute, true},
		{domain.PurposePhoneVerify, true, "phone_verify", 10 * time.Minute, true},
		{domain.Purpose(0), false, "unknown", 0, false},
		{domain.Purpose(99), false, "unknown", 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.str, func(t *testing.T) {
			if got := tc.purpose.Valid(); got != tc.valid {
				t.Errorf("Valid() = %v, want %v", got, tc.valid)
			}
			if got := tc.purpose.String(); got != tc.str {
				t.Errorf("String() = %q, want %q", got, tc.str)
			}
			ttl, ok := tc.purpose.TTL()
			if ok != tc.wantOkTTL || ttl != tc.wantTTL {
				t.Errorf("TTL() = (%v, %v), want (%v, %v)", ttl, ok, tc.wantTTL, tc.wantOkTTL)
			}
		})
	}
}

// --- NewVerificationToken --------------------------------------------------

func TestNewVerificationToken(t *testing.T) {
	t.Run("ok and field invariants", func(t *testing.T) {
		tok := mustVerificationToken(t, domain.PurposeMagicLink)
		if tok.ID().IsZero() {
			t.Error("id not set")
		}
		if tok.Purpose() != domain.PurposeMagicLink {
			t.Errorf("purpose = %v, want magic_link", tok.Purpose())
		}
		// createdAt is exactly the instant passed; expiry derives from it + TTL.
		if !tok.CreatedAt().Equal(timeFixed()) {
			t.Errorf("createdAt = %v, want %v", tok.CreatedAt(), timeFixed())
		}
		if !tok.ExpiresAt().Equal(timeFixed().Add(15 * time.Minute)) {
			t.Error("expiresAt != createdAt + purpose TTL")
		}
		if tok.IsConsumed() {
			t.Error("new token should not be consumed")
		}
		if _, ok := tok.ConsumedAt(); ok {
			t.Error("ConsumedAt ok should be false on new token")
		}
	})

	uid := domain.NewUserID()
	hash := func(t *testing.T) domain.TokenHash { return mustTokenHash(t, []byte("h")) }

	tests := []struct {
		name      string
		userID    domain.UserID
		purpose   domain.Purpose
		tokenHash domain.TokenHash
		wantErr   error
	}{
		{"zero userID", domain.UserID{}, domain.PurposeEmailVerify, hash(t), domain.ErrInvalidUserID},
		{"empty token hash", uid, domain.PurposeEmailVerify, domain.TokenHash{}, domain.ErrEmptyTokenHash},
		{"invalid purpose", uid, domain.Purpose(0), hash(t), domain.ErrInvalidPurpose},
		{"unknown purpose without ttl", uid, domain.Purpose(99), hash(t), domain.ErrInvalidPurpose},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := domain.NewVerificationToken(timeFixed(), tc.userID, tc.purpose, tc.tokenHash)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// --- IsExpired / IsConsumed / IsValid --------------------------------------

func TestVerificationTokenQueries(t *testing.T) {
	tok := mustVerificationToken(t, domain.PurposeMagicLink)
	at := tok.CreatedAt()

	tests := []struct {
		name        string
		now         time.Time
		wantExpired bool
	}{
		{"within window", at.Add(time.Minute), false},
		{"boundary exact", at.Add(15 * time.Minute), false},
		{"past deadline", at.Add(15*time.Minute + time.Second), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tok.IsExpired(tc.now); got != tc.wantExpired {
				t.Errorf("IsExpired = %v, want %v", got, tc.wantExpired)
			}
			// unconsumed token: valid iff not expired
			if got := tok.IsValid(tc.now); got != !tc.wantExpired {
				t.Errorf("IsValid = %v, want %v", got, !tc.wantExpired)
			}
		})
	}
}

func TestVerificationTokenIsValidWhenConsumed(t *testing.T) {
	tok := mustVerificationToken(t, domain.PurposeEmailVerify)
	if err := tok.Consume(timeFixed().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	// consumed token is never valid, even well within its window.
	if tok.IsValid(timeFixed().Add(2 * time.Minute)) {
		t.Error("consumed token reported valid")
	}
}

// --- Consume ---------------------------------------------------------------

func TestVerificationTokenConsume(t *testing.T) {
	t.Run("ok marks consumed with stamp", func(t *testing.T) {
		tok := mustVerificationToken(t, domain.PurposePasswordReset)
		consumedAt := timeFixed().Add(time.Minute)
		if err := tok.Consume(consumedAt); err != nil {
			t.Fatalf("Consume: %v", err)
		}
		if !tok.IsConsumed() {
			t.Error("token not marked consumed")
		}
		if ts, ok := tok.ConsumedAt(); !ok || !ts.Equal(consumedAt) {
			t.Errorf("consumedAt = %v, want %v", ts, consumedAt)
		}
	})

	t.Run("double consume rejected", func(t *testing.T) {
		tok := mustVerificationToken(t, domain.PurposePasswordReset)
		if err := tok.Consume(timeFixed().Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		if err := tok.Consume(timeFixed().Add(2 * time.Minute)); !errors.Is(err, domain.ErrTokenConsumed) {
			t.Errorf("err = %v, want ErrTokenConsumed", err)
		}
	})

	t.Run("expired rejected", func(t *testing.T) {
		tok, now := reconstituteExpiredToken(t)
		if err := tok.Consume(now); !errors.Is(err, domain.ErrTokenExpired) {
			t.Errorf("err = %v, want ErrTokenExpired", err)
		}
		if tok.IsConsumed() {
			t.Error("expired token must not be marked consumed")
		}
	})
}

// --- Reconstitute ----------------------------------------------------------

func TestReconstituteVerificationToken(t *testing.T) {
	id := domain.NewVerificationTokenID()
	uid := domain.NewUserID()
	hash := mustTokenHash(t, []byte("h"))
	created := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	consumed := created.Add(30 * time.Minute)

	tok := domain.ReconstituteVerificationToken(
		id, uid, domain.PurposePasswordReset, hash,
		created, created.Add(time.Hour), &consumed,
	)

	if tok.ID() != id || tok.UserID() != uid || tok.Purpose() != domain.PurposePasswordReset {
		t.Error("reconstitute did not preserve core fields")
	}
	if !bytes.Equal(tok.TokenHash().Bytes(), []byte("h")) {
		t.Errorf("tokenHash = %q, want h", tok.TokenHash().Bytes())
	}
	if !tok.CreatedAt().Equal(created) || !tok.ExpiresAt().Equal(created.Add(time.Hour)) {
		t.Error("reconstitute did not preserve timestamps")
	}
	if ts, ok := tok.ConsumedAt(); !ok || !ts.Equal(consumed) {
		t.Error("reconstitute did not preserve consumedAt")
	}
	if !tok.IsConsumed() {
		t.Error("reconstituted consumed token should report consumed")
	}
}
