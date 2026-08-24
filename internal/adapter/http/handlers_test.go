package httpapi_test

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"authentication/internal/adapter/crypto"
	httpapi "authentication/internal/adapter/http"
	"authentication/internal/adapter/mailer"
	"authentication/internal/adapter/memory"
	"authentication/internal/adapter/ratelimit"
	"authentication/internal/adapter/screener"
	"authentication/internal/adapter/text"
	"authentication/internal/app"
	"authentication/internal/domain"
	"authentication/internal/port"
)

var tokenRe = regexp.MustCompile(`token=([^\s]+)`)

type testEnv struct {
	srv     *httptest.Server
	handler http.Handler // the same router, for tests that forge RemoteAddr
	client  *http.Client
	mailLog *bytes.Buffer
}

// generousLimits are rate limits no functional test can reach, so a throttle
// never masquerades as a behavioural failure. The limits themselves are proven
// in middleware_test.go, which builds deliberately tiny ones.
func generousLimits() httpapi.Limits {
	l := func() port.RateLimiter { return ratelimit.NewMemory(100_000, time.Minute, systemClock{}) }
	return httpapi.Limits{Login: l(), Register: l(), Forgot: l(), Resend: l()}
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	return newTestEnvWithLimits(t, generousLimits())
}

func newTestEnvWithLimits(t *testing.T, limits httpapi.Limits) *testEnv {
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
		Limits:             limits,
		Register:           app.NewRegisterService(store.Users(), store.Credentials(), store.Tokens(), ml, tg, clk, nz, policy, sc, bc),
		VerifyEmail:        app.NewVerifyEmailService(store.Users(), store.Tokens(), tg, clk),
		ResendVerification: app.NewResendVerificationService(store.Users(), store.Tokens(), ml, tg, clk),
		Login:              app.NewLoginService(store.Users(), store.Credentials(), store.Sessions(), bc, tg, bc, nz, clk, 30*time.Minute, 24*time.Hour),
		ValidateSession:    app.NewValidateSessionService(store.Sessions(), tg, clk),
		Logout:             app.NewLogoutService(store.Sessions(), tg, clk),
		ChangePassword:     app.NewChangePasswordService(store.Credentials(), store.Sessions(), bc, nz, policy, sc, bc, clk),
		ForgotPassword:     app.NewForgotPasswordService(store.Users(), store.Tokens(), ml, tg, clk),
		ResetPassword:      app.NewResetPasswordService(store.Credentials(), store.Sessions(), store.Tokens(), tg, nz, policy, sc, bc, clk),
	}
	// CookieSecure must be false so the test client sends the cookie over httptest's http.
	opts := httpapi.Options{CookieSecure: false, SessionTTL: 24 * time.Hour, CSRFKey: testCSRFKey}

	handler := httpapi.NewRouter(deps, opts)
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	jar, _ := cookiejar.New(nil)
	return &testEnv{srv: srv, handler: handler, client: &http.Client{Jar: jar}, mailLog: &buf}
}

// systemClock is the real clock; HTTP tests don't manipulate time.
type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }

// testCSRFKey is a fixed server key; the tokens it signs are still random per
// session because the nonce is.
var testCSRFKey = []byte("test-csrf-key-at-least-32-bytes-long")

// post behaves like a browser frontend: it lets the jar carry the cookies and
// echoes the CSRF cookie in the X-CSRF-Token header, which is exactly what a
// cross-site attacker cannot do. Tests that need a request WITHOUT a valid
// token build it by hand (see middleware_test.go).
func (e *testEnv) post(t *testing.T, path string, body any) *http.Response {
	t.Helper()
	b, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, e.srv.URL+path, bytes.NewReader(b))
	if err != nil {
		t.Fatalf("build POST %s: %v", path, err)
	}
	req.Header.Set("Content-Type", "application/json")
	if tok := e.csrfToken(); tok != "" {
		req.Header.Set("X-CSRF-Token", tok)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	return resp
}

// csrfToken reads the CSRF cookie the way a frontend would — it is not
// HttpOnly, so JS (and the jar) can see it. Empty before any login.
func (e *testEnv) csrfToken() string {
	u, err := url.Parse(e.srv.URL)
	if err != nil {
		return ""
	}
	for _, c := range e.client.Jar.Cookies(u) {
		if c.Name == "csrf_token" {
			return c.Value
		}
	}
	return ""
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
	// The session that made the change survives it (ADR 0017): the user stays on
	// the page they were on, and only their other sessions are evicted.
	if resp := e.get(t, "/auth/me"); resp.StatusCode != http.StatusOK {
		t.Errorf("/me after change = %d, want 200 (the calling session is kept)", resp.StatusCode)
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

// readAll returns a response's status and body, closing it. Used where a test
// must compare two responses byte for byte.
func readAll(t *testing.T, resp *http.Response) (int, string) {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, string(b)
}

// TestResendVerificationIsIndistinguishable is the enumeration guard on the
// resend route: a pending account, an unregistered address, and an
// already-verified one must produce the same status AND the same bytes, or the
// endpoint becomes an account-existence oracle.
func TestResendVerificationIsIndistinguishable(t *testing.T) {
	e := newTestEnv(t)

	// A pending (registered, unverified) account.
	if resp := e.post(t, "/auth/register", map[string]string{"email": "pending@example.com", "password": goodPassword}); resp.StatusCode != http.StatusCreated {
		t.Fatalf("register pending: %d", resp.StatusCode)
	}
	_ = e.lastToken(t) // drop the registration token and clear the log

	// An account that completed verification.
	e.registerVerifyLogin(t, "done@example.com")

	pendingStatus, pendingBody := readAll(t, e.post(t, "/auth/verify-email/resend", map[string]string{"email": "pending@example.com"}))
	unknownStatus, unknownBody := readAll(t, e.post(t, "/auth/verify-email/resend", map[string]string{"email": "ghost@example.com"}))
	doneStatus, doneBody := readAll(t, e.post(t, "/auth/verify-email/resend", map[string]string{"email": "done@example.com"}))

	if pendingStatus != http.StatusAccepted {
		t.Errorf("resend pending = %d, want 202", pendingStatus)
	}
	if unknownStatus != pendingStatus || doneStatus != pendingStatus {
		t.Errorf("statuses differ: pending=%d unknown=%d verified=%d; all must match",
			pendingStatus, unknownStatus, doneStatus)
	}
	if unknownBody != pendingBody || doneBody != pendingBody {
		t.Errorf("bodies differ: pending=%q unknown=%q verified=%q; all must match",
			pendingBody, unknownBody, doneBody)
	}
}

// TestResendVerificationMailsAUsableToken proves the route does the work, not
// just that it stays quiet: the resent token must complete verification.
func TestResendVerificationMailsAUsableToken(t *testing.T) {
	e := newTestEnv(t)
	const email = "resend@example.com"

	if resp := e.post(t, "/auth/register", map[string]string{"email": email, "password": goodPassword}); resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: %d", resp.StatusCode)
	}
	_ = e.lastToken(t) // pretend the registration mail was lost

	if resp := e.post(t, "/auth/verify-email/resend", map[string]string{"email": email}); resp.StatusCode != http.StatusAccepted {
		t.Fatalf("resend = %d, want 202", resp.StatusCode)
	}
	tok := e.lastToken(t)

	if resp := e.post(t, "/auth/verify-email", map[string]string{"token": tok}); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("verify with resent token = %d, want 204", resp.StatusCode)
	}
	if resp := e.post(t, "/auth/login", map[string]string{"email": email, "password": goodPassword}); resp.StatusCode != http.StatusOK {
		t.Errorf("login after resent verification = %d, want 200", resp.StatusCode)
	}
}

// TestResendVerificationUnknownEmailMailsNothing pins the other half of the
// enumeration contract: identical responses must not be paid for by quietly
// mailing strangers.
func TestResendVerificationUnknownEmailMailsNothing(t *testing.T) {
	e := newTestEnv(t)
	e.mailLog.Reset()

	if resp := e.post(t, "/auth/verify-email/resend", map[string]string{"email": "ghost@example.com"}); resp.StatusCode != http.StatusAccepted {
		t.Fatalf("resend unknown = %d, want 202", resp.StatusCode)
	}
	if tokenRe.MatchString(e.mailLog.String()) {
		t.Error("unknown address triggered a verification mail")
	}
}
