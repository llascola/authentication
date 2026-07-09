package app_test

import (
	"errors"
	"testing"
	"time"

	"authentication/internal/app"
	"authentication/internal/domain"
)

// resetToken registers, verifies, and starts a reset, returning the raw reset
// token and the account email.
func resetToken(t *testing.T, h *harness, email string) string {
	t.Helper()
	h.registerAndVerify(t, email)
	if err := h.forgot.ForgotPassword(ctx, email); err != nil {
		t.Fatalf("ForgotPassword: %v", err)
	}
	return h.lastMailedToken(t)
}

func TestResetPasswordHappyPath(t *testing.T) {
	h := newHarness(t)
	email := "rp@example.com"

	// Log in first so there is a live session to be revoked by the reset.
	sessionTok := loginToken(t, h, email)
	if err := h.forgot.ForgotPassword(ctx, email); err != nil {
		t.Fatalf("ForgotPassword: %v", err)
	}
	resetTok := h.lastMailedToken(t)

	if err := h.reset.ResetPassword(ctx, resetTok, newPassword); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}

	// New password works; old does not.
	if _, err := h.login.Login(ctx, email, newPassword, testDevice(t)); err != nil {
		t.Errorf("login with new password = %v, want success", err)
	}
	if _, err := h.login.Login(ctx, email, goodPassword, testDevice(t)); !errors.Is(err, app.ErrAuthFailed) {
		t.Errorf("login with old password = %v, want ErrAuthFailed", err)
	}
	// All sessions revoked.
	if _, err := h.validate.Validate(ctx, sessionTok); !errors.Is(err, app.ErrNotAuthenticated) {
		t.Errorf("session after reset = %v, want ErrNotAuthenticated", err)
	}
}

func TestResetPasswordExpiredToken(t *testing.T) {
	h := newHarness(t)
	tok := resetToken(t, h, "rpe@example.com")
	h.clock.advance(2 * time.Hour) // past the 1h reset TTL
	if err := h.reset.ResetPassword(ctx, tok, newPassword); !errors.Is(err, app.ErrInvalidToken) {
		t.Errorf("expired reset = %v, want ErrInvalidToken", err)
	}
}

func TestResetPasswordReusedToken(t *testing.T) {
	h := newHarness(t)
	tok := resetToken(t, h, "rpr@example.com")
	if err := h.reset.ResetPassword(ctx, tok, newPassword); err != nil {
		t.Fatalf("first ResetPassword: %v", err)
	}
	if err := h.reset.ResetPassword(ctx, tok, "yet another long passphrase!!"); !errors.Is(err, app.ErrInvalidToken) {
		t.Errorf("reused reset = %v, want ErrInvalidToken", err)
	}
}

func TestResetPasswordWrongPurposeToken(t *testing.T) {
	h := newHarness(t)
	// An email-verify token must not work for reset.
	verifyTok := registerGetToken(t, h, "rpwp@example.com")
	if err := h.reset.ResetPassword(ctx, verifyTok, newPassword); !errors.Is(err, app.ErrInvalidToken) {
		t.Errorf("wrong-purpose reset = %v, want ErrInvalidToken", err)
	}
}

func TestResetPasswordWeakNew(t *testing.T) {
	h := newHarness(t)
	tok := resetToken(t, h, "rpwk@example.com")
	if err := h.reset.ResetPassword(ctx, tok, "short"); !errors.Is(err, domain.ErrPasswordTooShort) {
		t.Errorf("weak new = %v, want ErrPasswordTooShort", err)
	}
	// A rejected password must NOT burn the reset link: retrying on the same
	// token with a valid password succeeds.
	if err := h.reset.ResetPassword(ctx, tok, newPassword); err != nil {
		t.Errorf("retry after weak = %v, want nil (token must survive rejection)", err)
	}
}
