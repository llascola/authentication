package app_test

import (
	"errors"
	"testing"

	"authentication/internal/app"
)

func TestResendVerificationPendingAccountGetsUsableToken(t *testing.T) {
	h := newHarness(t)
	email := h.registerPending(t, "rv@example.com")

	if err := h.resend.ResendVerification(ctx, email); err != nil {
		t.Fatalf("ResendVerification: %v", err)
	}
	tok := h.lastMailedToken(t)
	if tok == "" {
		t.Fatal("pending account issued no verification token")
	}
	// The resent token must actually verify — proving the purpose is
	// PurposeEmailVerify and not a reset token.
	if err := h.verify.VerifyEmail(ctx, tok); err != nil {
		t.Errorf("VerifyEmail with resent token = %v, want nil", err)
	}
}

func TestResendVerificationInvalidatesPriorToken(t *testing.T) {
	h := newHarness(t)

	if err := h.register.Register(ctx, "rv2@example.com", goodPassword); err != nil {
		t.Fatalf("Register: %v", err)
	}
	registrationTok := h.lastMailedToken(t)

	if err := h.resend.ResendVerification(ctx, "rv2@example.com"); err != nil {
		t.Fatalf("ResendVerification: %v", err)
	}
	resentTok := h.lastMailedToken(t)
	if resentTok == registrationTok {
		t.Fatal("resend reused the registration token; want a freshly minted one")
	}

	// Only the newest token stays valid (ADR 0009, enforced by the repository).
	if err := h.verify.VerifyEmail(ctx, registrationTok); !errors.Is(err, app.ErrInvalidToken) {
		t.Errorf("verify with superseded token = %v, want ErrInvalidToken", err)
	}
	if err := h.verify.VerifyEmail(ctx, resentTok); err != nil {
		t.Errorf("verify with resent token = %v, want nil", err)
	}
}

// TestResendVerificationNonIssuingBranchesAreIdentical pins the enumeration
// contract: every case that must not issue a token has to be indistinguishable
// from the others at the service boundary — same nil error, no mail. A caller
// therefore learns nothing about whether an address is registered, already
// verified, or closed.
func TestResendVerificationNonIssuingBranchesAreIdentical(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, h *harness) string
	}{
		{
			name: "malformed email",
			setup: func(_ *testing.T, _ *harness) string {
				return "not-an-email"
			},
		},
		{
			name: "unknown account",
			setup: func(_ *testing.T, _ *harness) string {
				return "nobody@example.com"
			},
		},
		{
			name: "already verified",
			setup: func(t *testing.T, h *harness) string {
				t.Helper()
				return h.registerAndVerify(t, "verified@example.com")
			},
		},
		{
			name: "terminal status",
			setup: func(t *testing.T, h *harness) string {
				t.Helper()
				email := h.registerPending(t, "closed@example.com")
				h.deactivate(t, email)
				return email
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			email := tc.setup(t, h)
			h.mailLog.Reset() // ignore anything the setup itself mailed

			if err := h.resend.ResendVerification(ctx, email); err != nil {
				t.Errorf("ResendVerification = %v, want nil", err)
			}
			if tokenRe.MatchString(h.mailLog.String()) {
				t.Error("issued a verification token; should issue nothing")
			}
		})
	}
}
