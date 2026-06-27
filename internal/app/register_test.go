package app_test

import (
	"errors"
	"testing"

	"authentication/internal/domain"
)

func TestRegisterHappyPath(t *testing.T) {
	h := newHarness(t)
	if err := h.register.Register(ctx, "new@example.com", goodPassword); err != nil {
		t.Fatalf("Register: %v", err)
	}
	// A verification token was mailed.
	if tok := h.lastMailedToken(t); tok == "" {
		t.Error("no verification token mailed")
	}
}

func TestRegisterRejectsWeakPassword(t *testing.T) {
	h := newHarness(t)
	err := h.register.Register(ctx, "weak@example.com", "short")
	if !errors.Is(err, domain.ErrPasswordTooShort) {
		t.Errorf("Register weak = %v, want ErrPasswordTooShort", err)
	}
}

func TestRegisterRejectsBadEmail(t *testing.T) {
	h := newHarness(t)
	if err := h.register.Register(ctx, "not-an-email", goodPassword); err == nil {
		t.Error("Register with bad email returned nil")
	}
}

func TestRegisterDuplicateEmailIsEnumerationSafe(t *testing.T) {
	h := newHarness(t)
	if err := h.register.Register(ctx, "dup@example.com", goodPassword); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	h.mailLog.Reset() // drop the first token

	// Second registration of the same email must look identical (nil) and issue
	// nothing — no leak that the address is taken.
	if err := h.register.Register(ctx, "dup@example.com", "a totally different password!!"); err != nil {
		t.Errorf("duplicate Register = %v, want nil", err)
	}
	if tokenRe.MatchString(h.mailLog.String()) {
		t.Error("duplicate Register issued a token; should issue nothing")
	}
}
