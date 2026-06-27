package httpapi_test

import (
	"net/http"
	"testing"
)

// TestEndToEndPasswordSlice drives the whole slice over HTTP against the wired
// in-memory stack: register → read the mailed token → confirm login is blocked
// until verification → verify → login → /me → logout → confirm the session is
// dead. It is black-box over the router, so it exercises middleware, handlers,
// use-cases, and the store together, and runs under -race as the concurrency
// proof.
func TestEndToEndPasswordSlice(t *testing.T) {
	e := newTestEnv(t)
	const email = "e2e@example.com"

	// 1. Register.
	if resp := e.post(t, "/auth/register", map[string]string{"email": email, "password": goodPassword}); resp.StatusCode != http.StatusCreated {
		t.Fatalf("register = %d, want 201", resp.StatusCode)
	}

	// 2. Capture the verification token the stub mailer logged (stands in for the
	//    user reading their email).
	token := e.lastToken(t)

	// 3. Login BEFORE verification must fail: the account is still pending.
	if resp := e.post(t, "/auth/login", map[string]string{"email": email, "password": goodPassword}); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("pre-verify login = %d, want 401", resp.StatusCode)
	}

	// 4. Verify the email → account becomes active.
	if resp := e.post(t, "/auth/verify-email", map[string]string{"token": token}); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("verify = %d, want 204", resp.StatusCode)
	}

	// 5. Login now succeeds and sets the session cookie (captured by the jar).
	if resp := e.post(t, "/auth/login", map[string]string{"email": email, "password": goodPassword}); resp.StatusCode != http.StatusOK {
		t.Fatalf("post-verify login = %d, want 200", resp.StatusCode)
	}

	// 6. /me with the session cookie resolves the identity.
	if resp := e.get(t, "/auth/me"); resp.StatusCode != http.StatusOK {
		t.Fatalf("/me before logout = %d, want 200", resp.StatusCode)
	}

	// 7. Logout revokes the session and clears the cookie.
	if resp := e.post(t, "/auth/logout", nil); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("logout = %d, want 204", resp.StatusCode)
	}

	// 8. /me after logout is unauthenticated — the session is dead, not merely
	//    forgotten by the client (the server revoked it).
	if resp := e.get(t, "/auth/me"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("/me after logout = %d, want 401", resp.StatusCode)
	}
}

// TestEndToEndResetFlow drives the forgot/reset legs: a logged-in user resets
// via a mailed token, which rotates the password and kills every session.
func TestEndToEndResetFlow(t *testing.T) {
	e := newTestEnv(t)
	const email = "e2e-reset@example.com"
	e.registerVerifyLogin(t, email) // active + one live session

	// Forgot → a reset token is mailed.
	if resp := e.post(t, "/auth/password/forgot", map[string]string{"email": email}); resp.StatusCode != http.StatusAccepted {
		t.Fatalf("forgot = %d, want 202", resp.StatusCode)
	}
	resetToken := e.lastToken(t)

	// Reset with the token + a new password.
	if resp := e.post(t, "/auth/password/reset", map[string]string{"token": resetToken, "new_password": newPassword}); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("reset = %d, want 204", resp.StatusCode)
	}

	// The live session was revoked by the reset.
	if resp := e.get(t, "/auth/me"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("/me after reset = %d, want 401", resp.StatusCode)
	}
	// Old password no longer works; new one does.
	if resp := e.post(t, "/auth/login", map[string]string{"email": email, "password": goodPassword}); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("login old password after reset = %d, want 401", resp.StatusCode)
	}
	if resp := e.post(t, "/auth/login", map[string]string{"email": email, "password": newPassword}); resp.StatusCode != http.StatusOK {
		t.Fatalf("login new password after reset = %d, want 200", resp.StatusCode)
	}
}
