package app_test

import (
	"errors"
	"testing"

	"authentication/internal/app"
)

func TestLoginSuccess(t *testing.T) {
	h := newHarness(t)
	email := h.registerAndVerify(t, "login@example.com")
	tok, err := h.login.Login(ctx, email, goodPassword, testDevice(t))
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if tok == "" {
		t.Error("Login returned empty session token")
	}
}

func TestLoginWrongPassword(t *testing.T) {
	h := newHarness(t)
	email := h.registerAndVerify(t, "wrongpw@example.com")
	if _, err := h.login.Login(ctx, email, "not the password", testDevice(t)); !errors.Is(err, app.ErrAuthFailed) {
		t.Errorf("wrong password = %v, want ErrAuthFailed", err)
	}
}

func TestLoginUnknownEmail(t *testing.T) {
	h := newHarness(t)
	if _, err := h.login.Login(ctx, "nobody@example.com", goodPassword, testDevice(t)); !errors.Is(err, app.ErrAuthFailed) {
		t.Errorf("unknown email = %v, want ErrAuthFailed", err)
	}
}

func TestLoginPendingAccountRejected(t *testing.T) {
	h := newHarness(t)
	// Register but do NOT verify: account stays pending.
	if err := h.register.Register(ctx, "pending@example.com", goodPassword); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := h.login.Login(ctx, "pending@example.com", goodPassword, testDevice(t)); !errors.Is(err, app.ErrAuthFailed) {
		t.Errorf("pending login = %v, want ErrAuthFailed", err)
	}
}

func TestLoginLocksAfterFiveFailures(t *testing.T) {
	h := newHarness(t)
	email := h.registerAndVerify(t, "lock@example.com")

	// Five consecutive wrong passwords trip the domain lockout (maxFailedLogins).
	for i := range 5 {
		if _, err := h.login.Login(ctx, email, "wrong", testDevice(t)); !errors.Is(err, app.ErrAuthFailed) {
			t.Fatalf("attempt %d = %v, want ErrAuthFailed", i, err)
		}
	}
	// Now even the CORRECT password is refused: the account is locked, and the
	// lock is indistinguishable from bad credentials.
	if _, err := h.login.Login(ctx, email, goodPassword, testDevice(t)); !errors.Is(err, app.ErrAuthFailed) {
		t.Errorf("locked login with correct password = %v, want ErrAuthFailed", err)
	}
}
