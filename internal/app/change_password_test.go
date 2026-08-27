package app_test

import (
	"errors"
	"testing"

	"authentication/internal/app"
	"authentication/internal/domain"
)

// loginIdentity registers, verifies, logs in, and returns the session token plus
// the authenticated Identity — which carries the session's stored hash, so a
// use-case can tell this session apart from the user's others.
func loginIdentity(t *testing.T, h *harness, email string) (string, app.Identity) {
	t.Helper()
	tok := loginToken(t, h, email)
	id, err := h.validate.Validate(ctx, tok)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	return tok, id
}

func TestChangePasswordHappyPath(t *testing.T) {
	h := newHarness(t)
	sessionTok, caller := loginIdentity(t, h, "cp@example.com")

	if err := h.change.ChangePassword(ctx, caller, goodPassword, newPassword); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}

	// Old password no longer works; new one does.
	if _, err := h.login.Login(ctx, "cp@example.com", goodPassword, testDevice(t)); !errors.Is(err, app.ErrAuthFailed) {
		t.Errorf("login with old password = %v, want ErrAuthFailed", err)
	}
	if _, err := h.login.Login(ctx, "cp@example.com", newPassword, testDevice(t)); err != nil {
		t.Errorf("login with new password = %v, want success", err)
	}
	// The session that made the change survives it (ADR 0017).
	if _, err := h.validate.Validate(ctx, sessionTok); err != nil {
		t.Errorf("initiating session after change = %v, want it still valid", err)
	}
}

// TestChangePasswordRevokesOtherSessions is the security half of ADR 0017:
// sparing the caller's session must not spare an attacker's. Every other
// session — including ones opened after the caller's — has to die.
func TestChangePasswordRevokesOtherSessions(t *testing.T) {
	h := newHarness(t)
	const email = "cp-multi@example.com"
	callerTok, caller := loginIdentity(t, h, email)

	// A second session for the same user, standing in for a stolen cookie.
	otherTok, err := h.login.Login(ctx, email, goodPassword, testDevice(t))
	if err != nil {
		t.Fatalf("second Login: %v", err)
	}
	if _, err := h.validate.Validate(ctx, otherTok); err != nil {
		t.Fatalf("second session invalid before the change: %v", err)
	}

	if err := h.change.ChangePassword(ctx, caller, goodPassword, newPassword); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}

	if _, err := h.validate.Validate(ctx, otherTok); !errors.Is(err, app.ErrNotAuthenticated) {
		t.Errorf("other session after change = %v, want ErrNotAuthenticated", err)
	}
	if _, err := h.validate.Validate(ctx, callerTok); err != nil {
		t.Errorf("initiating session after change = %v, want it still valid", err)
	}
}

// TestChangePasswordWithoutSessionRevokesEverything pins the degenerate case: a
// zero SessionHash spares nothing, so a caller that fails to supply its session
// fails toward revoking too much rather than too little.
func TestChangePasswordWithoutSessionRevokesEverything(t *testing.T) {
	h := newHarness(t)
	sessionTok, caller := loginIdentity(t, h, "cp-nosess@example.com")

	bare := app.Identity{UserID: caller.UserID, AuthLevel: caller.AuthLevel} // no SessionHash
	if err := h.change.ChangePassword(ctx, bare, goodPassword, newPassword); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	if _, err := h.validate.Validate(ctx, sessionTok); !errors.Is(err, app.ErrNotAuthenticated) {
		t.Errorf("session after a change with no caller session = %v, want ErrNotAuthenticated", err)
	}
}

// TestChangePasswordDoesNotSpareAnotherUsersSession guards the obvious
// cross-tenant mistake: the keep hash must only ever exempt a session belonging
// to the user whose password changed.
func TestChangePasswordDoesNotSpareAnotherUsersSession(t *testing.T) {
	h := newHarness(t)
	_, caller := loginIdentity(t, h, "cp-mine@example.com")
	strangerTok, _ := loginIdentity(t, h, "cp-theirs@example.com")

	if err := h.change.ChangePassword(ctx, caller, goodPassword, newPassword); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	// A different user's session is untouched — the sweep is scoped by user id.
	if _, err := h.validate.Validate(ctx, strangerTok); err != nil {
		t.Errorf("another user's session after the change = %v, want it untouched", err)
	}
}

func TestChangePasswordWrongCurrent(t *testing.T) {
	h := newHarness(t)
	_, caller := loginIdentity(t, h, "cpw@example.com")
	if err := h.change.ChangePassword(ctx, caller, "wrong current", newPassword); !errors.Is(err, app.ErrAuthFailed) {
		t.Errorf("wrong current = %v, want ErrAuthFailed", err)
	}
}

func TestChangePasswordWeakNew(t *testing.T) {
	h := newHarness(t)
	_, caller := loginIdentity(t, h, "cpn@example.com")
	if err := h.change.ChangePassword(ctx, caller, goodPassword, "short"); !errors.Is(err, domain.ErrPasswordTooShort) {
		t.Errorf("weak new = %v, want ErrPasswordTooShort", err)
	}
}
