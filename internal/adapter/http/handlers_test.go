package httpapi_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"authentication/internal/adapter/crypto"
	httpapi "authentication/internal/adapter/http"
	"authentication/internal/adapter/mailer"
	"authentication/internal/adapter/memory"
	"authentication/internal/adapter/screener"
	"authentication/internal/adapter/text"
	"authentication/internal/app"
	"authentication/internal/domain"
)

var tokenRe = regexp.MustCompile(`token=([^\s]+)`)

type testEnv struct {
	srv     *httptest.Server
	client  *http.Client
	mailLog *bytes.Buffer
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	store := memory.NewStore()
	bc := crypto.NewBcrypt(4)
	tg := crypto.TokenGen{}
	nz := text.NFC{}
	sc := screener.NoOp{}
	clk := systemClock{}
	policy := domain.DefaultPasswordPolicy()

	var buf bytes.Buffer
	ml := mailer.NewLogMailer(slog.New(slog.NewTextHandler(&buf, nil)))

	deps := httpapi.Deps{
		Register:        app.NewRegisterService(store.Users(), store.Credentials(), store.Tokens(), ml, tg, clk, nz, policy, sc, bc),
		VerifyEmail:     app.NewVerifyEmailService(store.Users(), store.Tokens(), tg, clk),
		Login:           app.NewLoginService(store.Users(), store.Credentials(), store.Sessions(), bc, tg, bc, nz, clk, 30*time.Minute, 24*time.Hour),
		ValidateSession: app.NewValidateSessionService(store.Sessions(), tg, clk),
		Logout:          app.NewLogoutService(store.Sessions(), tg, clk),
		ChangePassword:  app.NewChangePasswordService(store.Credentials(), store.Sessions(), bc, nz, policy, sc, bc, clk),
		ForgotPassword:  app.NewForgotPasswordService(store.Users(), store.Tokens(), ml, tg, clk),
		ResetPassword:   app.NewResetPasswordService(store.Credentials(), store.Sessions(), store.Tokens(), tg, nz, policy, sc, bc, clk),
	}
	// CookieSecure must be false so the test client sends the cookie over httptest's http.
	opts := httpapi.Options{CookieSecure: false, SessionTTL: 24 * time.Hour}

	srv := httptest.NewServer(httpapi.NewRouter(deps, opts))
	t.Cleanup(srv.Close)

	jar, _ := cookiejar.New(nil)
	return &testEnv{srv: srv, client: &http.Client{Jar: jar}, mailLog: &buf}
}

// systemClock is the real clock; HTTP tests don't manipulate time.
type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }

func (e *testEnv) post(t *testing.T, path string, body any) *http.Response {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := e.client.Post(e.srv.URL+path, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	return resp
}

func (e *testEnv) get(t *testing.T, path string) *http.Response {
	t.Helper()
	resp, err := e.client.Get(e.srv.URL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	return resp
}

func (e *testEnv) lastToken(t *testing.T) string {
	t.Helper()
	m := tokenRe.FindAllStringSubmatch(e.mailLog.String(), -1)
	if len(m) == 0 {
		t.Fatal("no token in mailer output")
	}
	e.mailLog.Reset()
	return m[len(m)-1][1]
}

const (
	goodPassword = "correct horse battery staple"
	newPassword  = "an even longer replacement passphrase 9000"
)

func (e *testEnv) registerVerifyLogin(t *testing.T, email string) {
	t.Helper()
	if resp := e.post(t, "/auth/register", map[string]string{"email": email, "password": goodPassword}); resp.StatusCode != http.StatusCreated {
		t.Fatalf("register status = %d, want 201", resp.StatusCode)
	}
	tok := e.lastToken(t)
	if resp := e.post(t, "/auth/verify-email", map[string]string{"token": tok}); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("verify status = %d, want 204", resp.StatusCode)
	}
	if resp := e.post(t, "/auth/login", map[string]string{"email": email, "password": goodPassword}); resp.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d, want 200", resp.StatusCode)
	}
}

func TestFullCookieRoundTrip(t *testing.T) {
	e := newTestEnv(t)
	e.registerVerifyLogin(t, "flow@example.com")

	// The login set a session cookie; /me must now resolve the identity.
	resp := e.get(t, "/auth/me")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/me status = %d, want 200", resp.StatusCode)
	}
	var me map[string]string
	json.NewDecoder(resp.Body).Decode(&me)
	resp.Body.Close()
	if me["user_id"] == "" {
		t.Error("/me returned no user_id")
	}
	if me["auth_level"] != "aal1" {
		t.Errorf("auth_level = %q, want aal1", me["auth_level"])
	}
}

func TestChangePasswordRoundTrip(t *testing.T) {
	e := newTestEnv(t)
	e.registerVerifyLogin(t, "cp@example.com")

	resp := e.post(t, "/auth/password/change", map[string]string{
		"old_password": goodPassword, "new_password": newPassword,
	})
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("change = %d, want 204", resp.StatusCode)
	}
	// Strict policy: the change revoked all sessions, so /me is now 401.
	if resp := e.get(t, "/auth/me"); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("/me after change = %d, want 401 (sessions revoked)", resp.StatusCode)
	}
	// The new password logs in.
	if resp := e.post(t, "/auth/login", map[string]string{"email": "cp@example.com", "password": newPassword}); resp.StatusCode != http.StatusOK {
		t.Errorf("login with new password = %d, want 200", resp.StatusCode)
	}
}

func TestLoginBadPasswordIs401(t *testing.T) {
	e := newTestEnv(t)
	e.registerVerifyLogin(t, "bad@example.com") // also leaves us logged in; irrelevant
	resp := e.post(t, "/auth/login", map[string]string{"email": "bad@example.com", "password": "wrong"})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("bad login status = %d, want 401", resp.StatusCode)
	}
}

func TestMeWithoutCookieIs401(t *testing.T) {
	e := newTestEnv(t)
	resp := e.get(t, "/auth/me")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("/me without cookie = %d, want 401", resp.StatusCode)
	}
}

func TestRegisterDuplicateIsIndistinguishable(t *testing.T) {
	e := newTestEnv(t)
	body := map[string]string{"email": "dup@example.com", "password": goodPassword}
	first := e.post(t, "/auth/register", body)
	second := e.post(t, "/auth/register", body)
	if first.StatusCode != http.StatusCreated || second.StatusCode != http.StatusCreated {
		t.Errorf("register statuses = %d, %d; both must be 201 (no enumeration)", first.StatusCode, second.StatusCode)
	}
}

func TestRegisterWeakPasswordIs400(t *testing.T) {
	e := newTestEnv(t)
	resp := e.post(t, "/auth/register", map[string]string{"email": "weak@example.com", "password": "short"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("weak register = %d, want 400", resp.StatusCode)
	}
}

func TestLogoutClearsAndInvalidates(t *testing.T) {
	e := newTestEnv(t)
	e.registerVerifyLogin(t, "lo@example.com")

	resp := e.post(t, "/auth/logout", nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("logout = %d, want 204", resp.StatusCode)
	}
	// The clear-cookie directive should have a past Max-Age.
	if sc := resp.Header.Get("Set-Cookie"); !strings.Contains(sc, "Max-Age=0") && !strings.Contains(sc, "Max-Age=-1") {
		t.Errorf("logout Set-Cookie did not clear the cookie: %q", sc)
	}
	// After the jar applies the cleared cookie, /me is unauthenticated.
	if resp := e.get(t, "/auth/me"); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("/me after logout = %d, want 401", resp.StatusCode)
	}
}

func TestForgotPasswordAlwaysAccepted(t *testing.T) {
	e := newTestEnv(t)
	// Unknown email still returns 202 — no enumeration.
	resp := e.post(t, "/auth/password/forgot", map[string]string{"email": "ghost@example.com"})
	if resp.StatusCode != http.StatusAccepted {
		t.Errorf("forgot unknown = %d, want 202", resp.StatusCode)
	}
}

func TestSessionCookieAttributes(t *testing.T) {
	e := newTestEnv(t)
	if resp := e.post(t, "/auth/register", map[string]string{"email": "ck@example.com", "password": goodPassword}); resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: %d", resp.StatusCode)
	}
	tok := e.lastToken(t)
	e.post(t, "/auth/verify-email", map[string]string{"token": tok})

	resp := e.post(t, "/auth/login", map[string]string{"email": "ck@example.com", "password": goodPassword})
	sc := resp.Header.Get("Set-Cookie")
	for _, want := range []string{"session=", "HttpOnly", "SameSite=Lax", "Path=/"} {
		if !strings.Contains(sc, want) {
			t.Errorf("Set-Cookie %q missing %q", sc, want)
		}
	}
}
