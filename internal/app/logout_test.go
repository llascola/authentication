package app_test

import (
	"errors"
	"testing"

	"authentication/internal/app"
)

func TestLogoutRevokesActiveSession(t *testing.T) {
	h := newHarness(t)
	tok := loginToken(t, h, "lo@example.com")
	if err := h.logout.Logout(ctx, tok); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	// Session no longer validates.
	if _, err := h.validate.Validate(ctx, tok); !errors.Is(err, app.ErrNotAuthenticated) {
		t.Errorf("validate after logout = %v, want ErrNotAuthenticated", err)
	}
}

func TestLogoutIsIdempotent(t *testing.T) {
	h := newHarness(t)
	tok := loginToken(t, h, "lo2@example.com")
	if err := h.logout.Logout(ctx, tok); err != nil {
		t.Fatalf("first Logout: %v", err)
	}
	// Second logout of an already-revoked session is a no-op success.
	if err := h.logout.Logout(ctx, tok); err != nil {
		t.Errorf("second Logout = %v, want nil", err)
	}
}

func TestLogoutUnknownTokenSucceeds(t *testing.T) {
	h := newHarness(t)
	if err := h.logout.Logout(ctx, "never-issued"); err != nil {
		t.Errorf("unknown Logout = %v, want nil", err)
	}
}
