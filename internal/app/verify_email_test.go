package app_test

import (
	"errors"
	"testing"
	"time"

	"authentication/internal/app"
)

func registerGetToken(t *testing.T, h *harness, email string) string {
	t.Helper()
	if err := h.register.Register(ctx, email, goodPassword); err != nil {
		t.Fatalf("Register: %v", err)
	}
	return h.lastMailedToken(t)
}

func TestVerifyEmailHappyPathActivates(t *testing.T) {
	h := newHarness(t)
	tok := registerGetToken(t, h, "verify@example.com")
	if err := h.verify.VerifyEmail(ctx, tok); err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}
	// Account is now active: login succeeds.
	if _, err := h.login.Login(ctx, "verify@example.com", goodPassword, testDevice(t)); err != nil {
		t.Errorf("login after verify = %v, want success", err)
	}
}

func TestVerifyEmailExpiredToken(t *testing.T) {
	h := newHarness(t)
	tok := registerGetToken(t, h, "exp@example.com")
	h.clock.advance(25 * time.Hour) // past the 24h email-verify TTL
	if err := h.verify.VerifyEmail(ctx, tok); !errors.Is(err, app.ErrInvalidToken) {
		t.Errorf("expired verify = %v, want ErrInvalidToken", err)
	}
}

func TestVerifyEmailReusedToken(t *testing.T) {
	h := newHarness(t)
	tok := registerGetToken(t, h, "reuse@example.com")
	if err := h.verify.VerifyEmail(ctx, tok); err != nil {
		t.Fatalf("first VerifyEmail: %v", err)
	}
	if err := h.verify.VerifyEmail(ctx, tok); !errors.Is(err, app.ErrInvalidToken) {
		t.Errorf("reused verify = %v, want ErrInvalidToken", err)
	}
}

func TestVerifyEmailWrongPurposeToken(t *testing.T) {
	h := newHarness(t)
	email := h.registerAndVerify(t, "wp@example.com")
	// Mint a password-reset token, then try to use it for email verification.
	if err := h.forgot.ForgotPassword(ctx, email); err != nil {
		t.Fatalf("ForgotPassword: %v", err)
	}
	resetTok := h.lastMailedToken(t)
	if err := h.verify.VerifyEmail(ctx, resetTok); !errors.Is(err, app.ErrInvalidToken) {
		t.Errorf("wrong-purpose verify = %v, want ErrInvalidToken", err)
	}
}

func TestVerifyEmailUnknownToken(t *testing.T) {
	h := newHarness(t)
	if err := h.verify.VerifyEmail(ctx, "totally-unknown-token"); !errors.Is(err, app.ErrInvalidToken) {
		t.Errorf("unknown verify = %v, want ErrInvalidToken", err)
	}
}
