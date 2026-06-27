package app_test

import (
	"errors"
	"testing"

	"authentication/internal/app"
)

func TestForgotPasswordKnownEmailIssuesToken(t *testing.T) {
	h := newHarness(t)
	email := h.registerAndVerify(t, "fp@example.com")
	if err := h.forgot.ForgotPassword(ctx, email); err != nil {
		t.Fatalf("ForgotPassword: %v", err)
	}
	if tok := h.lastMailedToken(t); tok == "" {
		t.Error("known email issued no reset token")
	}
}

func TestForgotPasswordUnknownEmailIsSilent(t *testing.T) {
	h := newHarness(t)
	if err := h.forgot.ForgotPassword(ctx, "nobody@example.com"); err != nil {
		t.Errorf("unknown ForgotPassword = %v, want nil", err)
	}
	if tokenRe.MatchString(h.mailLog.String()) {
		t.Error("unknown email issued a reset token; should issue nothing")
	}
}

func TestForgotPasswordReissueInvalidatesPrior(t *testing.T) {
	h := newHarness(t)
	email := h.registerAndVerify(t, "fp2@example.com")

	if err := h.forgot.ForgotPassword(ctx, email); err != nil {
		t.Fatalf("first ForgotPassword: %v", err)
	}
	firstTok := h.lastMailedToken(t)

	if err := h.forgot.ForgotPassword(ctx, email); err != nil {
		t.Fatalf("second ForgotPassword: %v", err)
	}
	_ = h.lastMailedToken(t) // discard second token

	// The first token must now be invalid (superseded by the second).
	if err := h.reset.ResetPassword(ctx, firstTok, newPassword); !errors.Is(err, app.ErrInvalidToken) {
		t.Errorf("reset with superseded token = %v, want ErrInvalidToken", err)
	}
}
