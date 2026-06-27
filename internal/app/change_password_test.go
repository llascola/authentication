package app_test

import (
	"errors"
	"testing"

	"authentication/internal/app"
	"authentication/internal/domain"
)

// loginIdentity registers, verifies, logs in, and returns the session token plus
// the authenticated UserID.
func loginIdentity(t *testing.T, h *harness, email string) (string, domain.UserID) {
	t.Helper()
	tok := loginToken(t, h, email)
	id, err := h.validate.Validate(ctx, tok)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	return tok, id.UserID
}

func TestChangePasswordHappyPath(t *testing.T) {
	h := newHarness(t)
	sessionTok, userID := loginIdentity(t, h, "cp@example.com")

	if err := h.change.ChangePassword(ctx, userID, goodPassword, newPassword); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}

	// Old password no longer works; new one does.
	if _, err := h.login.Login(ctx, "cp@example.com", goodPassword, testDevice(t)); !errors.Is(err, app.ErrAuthFailed) {
		t.Errorf("login with old password = %v, want ErrAuthFailed", err)
	}
	if _, err := h.login.Login(ctx, "cp@example.com", newPassword, testDevice(t)); err != nil {
		t.Errorf("login with new password = %v, want success", err)
	}
	// Existing sessions were revoked (strict policy: all sessions killed).
	if _, err := h.validate.Validate(ctx, sessionTok); !errors.Is(err, app.ErrNotAuthenticated) {
		t.Errorf("old session after change = %v, want ErrNotAuthenticated", err)
	}
}

func TestChangePasswordWrongCurrent(t *testing.T) {
	h := newHarness(t)
	_, userID := loginIdentity(t, h, "cpw@example.com")
	if err := h.change.ChangePassword(ctx, userID, "wrong current", newPassword); !errors.Is(err, app.ErrAuthFailed) {
		t.Errorf("wrong current = %v, want ErrAuthFailed", err)
	}
}

func TestChangePasswordWeakNew(t *testing.T) {
	h := newHarness(t)
	_, userID := loginIdentity(t, h, "cpn@example.com")
	if err := h.change.ChangePassword(ctx, userID, goodPassword, "short"); !errors.Is(err, domain.ErrPasswordTooShort) {
		t.Errorf("weak new = %v, want ErrPasswordTooShort", err)
	}
}
