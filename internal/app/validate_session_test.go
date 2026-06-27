package app_test

import (
	"errors"
	"testing"
	"time"

	"authentication/internal/app"
	"authentication/internal/domain"
)

// loginToken registers, verifies, and logs in, returning the raw session token.
func loginToken(t *testing.T, h *harness, email string) string {
	t.Helper()
	h.registerAndVerify(t, email)
	tok, err := h.login.Login(ctx, email, goodPassword, testDevice(t))
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	return tok
}

func TestValidateSessionActive(t *testing.T) {
	h := newHarness(t)
	tok := loginToken(t, h, "vs@example.com")
	id, err := h.validate.Validate(ctx, tok)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if id.UserID.IsZero() {
		t.Error("Validate returned zero UserID")
	}
	if id.AuthLevel != domain.AAL1 {
		t.Errorf("AuthLevel = %v, want AAL1", id.AuthLevel)
	}
}

func TestValidateSessionIdleExpired(t *testing.T) {
	h := newHarness(t)
	tok := loginToken(t, h, "idle@example.com")
	h.clock.advance(2 * time.Hour) // past the 1h idle TTL
	if _, err := h.validate.Validate(ctx, tok); !errors.Is(err, app.ErrNotAuthenticated) {
		t.Errorf("idle-expired validate = %v, want ErrNotAuthenticated", err)
	}
}

func TestValidateSessionRevoked(t *testing.T) {
	h := newHarness(t)
	tok := loginToken(t, h, "rev@example.com")
	if err := h.logout.Logout(ctx, tok); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if _, err := h.validate.Validate(ctx, tok); !errors.Is(err, app.ErrNotAuthenticated) {
		t.Errorf("revoked validate = %v, want ErrNotAuthenticated", err)
	}
}

func TestValidateSessionUnknown(t *testing.T) {
	h := newHarness(t)
	if _, err := h.validate.Validate(ctx, "unknown-cookie-value"); !errors.Is(err, app.ErrNotAuthenticated) {
		t.Errorf("unknown validate = %v, want ErrNotAuthenticated", err)
	}
}
