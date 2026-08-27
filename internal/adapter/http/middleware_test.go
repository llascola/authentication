package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	httpapi "authentication/internal/adapter/http"
	"authentication/internal/adapter/ratelimit"
	"authentication/internal/port"
)

// tightLimits builds a real limiter of the given size for one route and leaves
// the others generous, so a test throttles exactly the route it is aiming at.
func tightLimits(route string, limit int) httpapi.Limits {
	l := generousLimits()
	tight := ratelimit.NewMemory(limit, time.Minute, systemClock{})
	switch route {
	case "login":
		l.Login = tight
	case "register":
		l.Register = tight
	case "forgot":
		l.Forgot = tight
	case "resend":
		l.Resend = tight
	default:
		panic("unknown route " + route)
	}
	return l
}

// postFrom drives the router directly so the test can choose the peer address —
// httptest's client always dials from 127.0.0.1, which cannot show that a
// per-email limit spans many sources.
func (e *testEnv) postFrom(t *testing.T, remoteAddr, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	req.RemoteAddr = remoteAddr
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	return rec
}

func TestRateLimitReturns429WithRetryAfter(t *testing.T) {
	const limit = 3
	e := newTestEnvWithLimits(t, tightLimits("login", limit))
	body := map[string]string{"email": "spray@example.com", "password": "wrong-password"}

	for i := range limit {
		if rec := e.postFrom(t, "198.51.100.9:1234", "/auth/login", body); rec.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d was throttled while still under the limit", i)
		}
	}

	rec := e.postFrom(t, "198.51.100.9:1234", "/auth/login", body)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("over-limit login = %d, want 429", rec.Code)
	}
	ra := rec.Header().Get("Retry-After")
	secs, err := strconv.Atoi(ra)
	if err != nil {
		t.Fatalf("Retry-After = %q, want an integer number of seconds", ra)
	}
	if secs < 1 {
		t.Errorf("Retry-After = %d, want >= 1", secs)
	}
}

// TestRateLimitIsIdenticalForUnknownAccounts is the oracle guard. If the limit
// were applied only after an account lookup succeeded, "throttled" would mean
// "this address is registered". Both cases must throttle at the same request
// and answer with the same bytes.
func TestRateLimitIsIdenticalForUnknownAccounts(t *testing.T) {
	const limit = 2

	run := func(t *testing.T, email string, register bool) (int, string) {
		t.Helper()
		e := newTestEnvWithLimits(t, tightLimits("forgot", limit))
		if register {
			if resp := e.post(t, "/auth/register", map[string]string{"email": email, "password": goodPassword}); resp.StatusCode != http.StatusCreated {
				t.Fatalf("register: %d", resp.StatusCode)
			}
		}
		body := map[string]string{"email": email}
		var rec *httptest.ResponseRecorder
		for range limit + 1 {
			rec = e.postFrom(t, "203.0.113.5:5555", "/auth/password/forgot", body)
		}
		return rec.Code, rec.Body.String()
	}

	knownCode, knownBody := run(t, "known@example.com", true)
	unknownCode, unknownBody := run(t, "ghost@example.com", false)

	if knownCode != http.StatusTooManyRequests {
		t.Fatalf("registered address over limit = %d, want 429", knownCode)
	}
	if unknownCode != knownCode {
		t.Errorf("statuses differ: registered=%d unregistered=%d; the limiter is an existence oracle",
			knownCode, unknownCode)
	}
	if unknownBody != knownBody {
		t.Errorf("bodies differ: registered=%q unregistered=%q", knownBody, unknownBody)
	}
}

// TestPerEmailLimitSpansSourceAddresses is the point of keying by email at all:
// a per-IP limit alone lets an attacker with a pool of addresses mail-bomb one
// inbox freely.
// postVia is postFrom with a forwarding header, for tests that put the server
// behind a proxy: every request shares one peer address (the proxy) and is told
// apart only by X-Forwarded-For.
func (e *testEnv) postVia(t *testing.T, remoteAddr, xff, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	req.RemoteAddr = remoteAddr
	req.Header.Set("X-Forwarded-For", xff)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	return rec
}

func TestPerEmailLimitSpansSourceAddresses(t *testing.T) {
	const limit = 2
	e := newTestEnvWithLimits(t, tightLimits("resend", limit))
	body := map[string]string{"email": "victim@example.com"}

	// Each request arrives from a different address, so the per-IP bucket is
	// untouched — only the per-email one accumulates.
	for i, addr := range []string{"192.0.2.1:1", "192.0.2.2:2"} {
		if rec := e.postFrom(t, addr, "/auth/verify-email/resend", body); rec.Code != http.StatusAccepted {
			t.Fatalf("request %d from %s = %d, want 202", i, addr, rec.Code)
		}
	}
	if rec := e.postFrom(t, "192.0.2.3:3", "/auth/verify-email/resend", body); rec.Code != http.StatusTooManyRequests {
		t.Errorf("third source = %d, want 429: the per-email limit must span source addresses", rec.Code)
	}
}

// TestPerIPLimitSpansEmails is the mirror: one source must not get a fresh
// budget by varying the address it submits, which is exactly what a spray does.
func TestPerIPLimitSpansEmails(t *testing.T) {
	const limit = 2
	e := newTestEnvWithLimits(t, tightLimits("login", limit))

	for i, email := range []string{"a@example.com", "b@example.com"} {
		rec := e.postFrom(t, "198.51.100.1:99", "/auth/login", map[string]string{"email": email, "password": "guess"})
		if rec.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d was throttled while still under the limit", i)
		}
	}
	rec := e.postFrom(t, "198.51.100.1:99", "/auth/login", map[string]string{"email": "c@example.com", "password": "guess"})
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("third email from one address = %d, want 429: a spray must not get a fresh budget per account", rec.Code)
	}
}

func TestRegisterIsRateLimited(t *testing.T) {
	const limit = 2
	e := newTestEnvWithLimits(t, tightLimits("register", limit))

	for i := range limit {
		body := map[string]string{"email": "flood" + strconv.Itoa(i) + "@example.com", "password": goodPassword}
		if rec := e.postFrom(t, "203.0.113.77:1", "/auth/register", body); rec.Code != http.StatusCreated {
			t.Fatalf("register %d = %d, want 201", i, rec.Code)
		}
	}
	body := map[string]string{"email": "flood-over@example.com", "password": goodPassword}
	if rec := e.postFrom(t, "203.0.113.77:1", "/auth/register", body); rec.Code != http.StatusTooManyRequests {
		t.Errorf("register over limit = %d, want 429", rec.Code)
	}
}

// TestRateLimitedRequestDoesNotReachTheHandler proves the throttle is placed
// before the work, not after it: a denied resend must send no mail.
func TestRateLimitedRequestDoesNotReachTheHandler(t *testing.T) {
	const limit = 1
	e := newTestEnvWithLimits(t, tightLimits("resend", limit))

	if resp := e.post(t, "/auth/register", map[string]string{"email": "quiet@example.com", "password": goodPassword}); resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: %d", resp.StatusCode)
	}
	_ = e.lastToken(t) // clears the mail log

	body := map[string]string{"email": "quiet@example.com"}
	if rec := e.postFrom(t, "192.0.2.50:1", "/auth/verify-email/resend", body); rec.Code != http.StatusAccepted {
		t.Fatalf("first resend = %d, want 202", rec.Code)
	}
	_ = e.lastToken(t) // that one was allowed; drop its token and clear the log

	if rec := e.postFrom(t, "192.0.2.50:1", "/auth/verify-email/resend", body); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second resend = %d, want 429", rec.Code)
	}
	if tokenRe.MatchString(e.mailLog.String()) {
		t.Error("a throttled request still sent mail; the limit must run before the handler")
	}
}

// failingLimiter stands in for a networked limiter that is down.
type failingLimiter struct{}

func (failingLimiter) Allow(context.Context, string) (bool, time.Duration, error) {
	return false, 0, errors.New("limiter backend unreachable")
}

var _ port.RateLimiter = failingLimiter{}

// TestLimiterFailureIsFailClosed pins the security decision: when the limiter
// cannot answer, the request is refused. Failing open would let an attacker who
// can break the limiter switch off every throttle at once.
func TestLimiterFailureIsFailClosed(t *testing.T) {
	limits := generousLimits()
	limits.Login = failingLimiter{}
	e := newTestEnvWithLimits(t, limits)

	rec := e.postFrom(t, "198.51.100.3:1", "/auth/login", map[string]string{"email": "x@example.com", "password": goodPassword})
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("login with a broken limiter = %d, want 503 (fail closed)", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("503 carried no Retry-After")
	}
}

func TestNewRouterPanicsOnMissingLimiter(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("NewRouter accepted a nil limiter; a route must never ship unthrottled")
		}
	}()
	limits := generousLimits()
	limits.Forgot = nil
	_ = newTestEnvWithLimits(t, limits)
}

// --- key derivation --------------------------------------------------------

func TestIPKeyUsesRemoteAddrOnlyByDefault(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	req.RemoteAddr = "198.51.100.4:5555"
	// A forged forwarding header must not change the key: a key the caller
	// controls is not a limit (ADR 0015 trusts no proxy header).
	req.Header.Set("X-Forwarded-For", "10.0.0.1")
	req.Header.Set("X-Real-IP", "10.0.0.2")

	key, ok := httpapi.IPKeyForTest(0)(req)
	if !ok {
		t.Fatal("ipKey returned no key for a normal request")
	}
	if !bytes.Contains([]byte(key), []byte("198.51.100.4")) {
		t.Errorf("key = %q, want it derived from RemoteAddr", key)
	}
	if bytes.Contains([]byte(key), []byte("10.0.0.")) {
		t.Errorf("key = %q, must not come from a proxy header", key)
	}
}

func TestEmailKeyCanonicalisesAndRestoresBody(t *testing.T) {
	newReq := func(body string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/auth/password/forgot", bytes.NewReader([]byte(body)))
		return r
	}

	mixed := newReq(`{"email":"  User@Example.COM  "}`)
	key, ok := httpapi.EmailKeyForTest(mixed)
	if !ok {
		t.Fatal("emailKey returned no key for a valid address")
	}
	lower := newReq(`{"email":"user@example.com"}`)
	lowerKey, ok := httpapi.EmailKeyForTest(lower)
	if !ok {
		t.Fatal("emailKey returned no key for the lowercase address")
	}
	if key != lowerKey {
		t.Errorf("keys differ: %q vs %q; case and whitespace must not buy a second budget", key, lowerKey)
	}

	// The handler still has to decode the body the middleware just read.
	rest, err := io.ReadAll(mixed.Body)
	if err != nil {
		t.Fatalf("read restored body: %v", err)
	}
	if string(rest) != `{"email":"  User@Example.COM  "}` {
		t.Errorf("restored body = %q, want the original bytes", rest)
	}
}

func TestEmailKeyDeclinesUnusableBodies(t *testing.T) {
	cases := map[string]string{
		"malformed json": `{"email":`,
		"no email field": `{"token":"abc"}`,
		"empty email":    `{"email":""}`,
		"invalid email":  `{"email":"not-an-address"}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/auth/password/forgot", bytes.NewReader([]byte(body)))
			if key, ok := httpapi.EmailKeyForTest(r); ok {
				t.Errorf("emailKey returned %q; an unusable body must yield no key", key)
			}
		})
	}
}

// --- CSRF ------------------------------------------------------------------

// cookieValue reads a cookie the jar holds for the test server.
func (e *testEnv) cookieValue(name string) string {
	u, err := url.Parse(e.srv.URL)
	if err != nil {
		return ""
	}
	for _, c := range e.client.Jar.Cookies(u) {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

// rawPost sends a request with cookies and header set explicitly, bypassing the
// jar — the only way to model a caller that has the session cookie (the browser
// attaches it) but not a usable token (a cross-site attacker cannot read it).
// An empty value omits that cookie or header entirely.
func (e *testEnv) rawPost(t *testing.T, path, session, csrfCookie, csrfHeader string, body any) *http.Response {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, e.srv.URL+path, bytes.NewReader(b))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if session != "" {
		req.AddCookie(&http.Cookie{Name: "session", Value: session})
	}
	if csrfCookie != "" {
		req.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrfCookie})
	}
	if csrfHeader != "" {
		req.Header.Set("X-CSRF-Token", csrfHeader)
	}
	// A bare client: no jar, so nothing is added behind the test's back.
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	return resp
}

func changeBody() map[string]string {
	return map[string]string{"old_password": goodPassword, "new_password": newPassword}
}

func TestCSRFValidTokenPasses(t *testing.T) {
	e := newTestEnv(t)
	e.registerVerifyLogin(t, "csrf-ok@example.com")
	session, token := e.cookieValue("session"), e.cookieValue("csrf_token")
	if token == "" {
		t.Fatal("login issued no CSRF cookie")
	}

	resp := e.rawPost(t, "/auth/password/change", session, token, token, changeBody())
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("change with a valid token = %d, want 204", resp.StatusCode)
	}
}

func TestCSRFRejections(t *testing.T) {
	// Each case describes one way a request can fail the check. All of them must
	// be the same 403 — the response says nothing about which.
	cases := map[string]func(session, token string) (csrfCookie, csrfHeader string){
		"missing header": func(_, token string) (string, string) {
			return token, ""
		},
		"missing cookie": func(_, token string) (string, string) {
			return "", token
		},
		"header does not match cookie": func(_, token string) (string, string) {
			return token, "some-other-value"
		},
		"tampered mac": func(_, token string) (string, string) {
			// Same nonce, flipped MAC: structurally valid, cryptographically not.
			nonce, _, _ := strings.Cut(token, ".")
			forged := nonce + ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
			return forged, forged
		},
		"not a token at all": func(_, _ string) (string, string) {
			return "garbage", "garbage"
		},
	}

	for name, forge := range cases {
		t.Run(name, func(t *testing.T) {
			e := newTestEnv(t)
			e.registerVerifyLogin(t, "csrf-bad@example.com")
			session, token := e.cookieValue("session"), e.cookieValue("csrf_token")

			csrfCookie, csrfHeader := forge(session, token)
			resp := e.rawPost(t, "/auth/password/change", session, csrfCookie, csrfHeader, changeBody())
			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("change with %s = %d, want 403", name, resp.StatusCode)
			}
		})
	}
}

// TestCSRFTokenIsBoundToItsSession is the part a plain double-submit scheme
// cannot do. An attacker who can set cookies on the domain (any subdomain) can
// make header and cookie agree; what they cannot do is produce a token this
// server minted for the VICTIM's session.
func TestCSRFTokenIsBoundToItsSession(t *testing.T) {
	e := newTestEnv(t)

	// Victim logs in; capture their session.
	e.registerVerifyLogin(t, "victim@example.com")
	victimSession := e.cookieValue("session")

	// Attacker logs in on the same server and gets a perfectly valid token —
	// for their own session.
	e.registerVerifyLogin(t, "attacker@example.com")
	attackerToken := e.cookieValue("csrf_token")
	if attackerToken == "" {
		t.Fatal("attacker login issued no CSRF cookie")
	}

	// Header and cookie agree, and the token is genuinely server-minted. It is
	// still bound to the wrong session.
	resp := e.rawPost(t, "/auth/password/change", victimSession, attackerToken, attackerToken, changeBody())
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("change with another session's token = %d, want 403", resp.StatusCode)
	}
}

// TestCSRFRunsBeforeSessionLookup: a forged request is refused at the token, not
// at the session. Otherwise a forged request would still reach ValidateSession
// and slide the victim's idle window, letting an attacker keep a session alive.
func TestCSRFRunsBeforeSessionLookup(t *testing.T) {
	e := newTestEnv(t)
	// A session cookie that is not a real session, and no CSRF token. If the
	// session were checked first this would be 401.
	resp := e.rawPost(t, "/auth/password/change", "not-a-real-session", "", "", changeBody())
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("forged request = %d, want 403 (CSRF checked before the session)", resp.StatusCode)
	}
}

// TestCSRFTokenRotatesOnPasswordChange covers ADR 0017's obligation as far as a
// stateless token can: the session survives a password change, so the client is
// handed a freshly minted token rather than carrying the old one onward.
func TestCSRFTokenRotatesOnPasswordChange(t *testing.T) {
	e := newTestEnv(t)
	e.registerVerifyLogin(t, "rotate@example.com")
	session, before := e.cookieValue("session"), e.cookieValue("csrf_token")

	if resp := e.post(t, "/auth/password/change", changeBody()); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("change = %d, want 204", resp.StatusCode)
	}
	after := e.cookieValue("csrf_token")

	if after == before {
		t.Error("CSRF token was not rotated by the password change")
	}
	if e.cookieValue("session") != session {
		t.Error("the session cookie changed; ADR 0017 keeps the session")
	}
	// The new token works.
	resp := e.rawPost(t, "/auth/password/change",
		session, after, after,
		map[string]string{"old_password": newPassword, "new_password": goodPassword})
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("change with the rotated token = %d, want 204", resp.StatusCode)
	}
}

// TestCSRFOldTokenStillVerifiesAfterRotation documents a KNOWN LIMITATION, and
// exists so nobody mistakes issuing a new token for revoking the old one.
//
// Verification is a stateless HMAC over (nonce | session token). The server
// keeps no record of which nonce is current, so every token it ever minted for
// a live session keeps verifying until that session ends. Rotation changes what
// the client holds; it cannot invalidate what someone else already holds.
//
// The residual risk is narrow — a CSRF token is useless without the HttpOnly
// session cookie, and a cross-site attacker cannot read the CSRF cookie to
// begin with — but it is real for anyone who once learned a token value.
//
// Closing it properly means rotating the SESSION bearer token on credential
// change (keeping the session aggregate, per ADR 0017, but re-keying it), which
// is domain and repository work, not edge work. Recorded in ADR 0018.
func TestCSRFOldTokenStillVerifiesAfterRotation(t *testing.T) {
	e := newTestEnv(t)
	e.registerVerifyLogin(t, "stale-token@example.com")
	session, before := e.cookieValue("session"), e.cookieValue("csrf_token")

	if resp := e.post(t, "/auth/password/change", changeBody()); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("change = %d, want 204", resp.StatusCode)
	}

	resp := e.rawPost(t, "/auth/password/change",
		session, before, before,
		map[string]string{"old_password": newPassword, "new_password": goodPassword})
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("pre-rotation token = %d, want 204. If this now fails, the "+
			"limitation this test documents has been fixed — delete it and update ADR 0018",
			resp.StatusCode)
	}
}

// TestLogoutWithoutSessionStaysIdempotent: the check only applies where there is
// ambient authority to abuse. No session cookie means nothing to forge, and
// logout must keep answering 204.
func TestLogoutWithoutSessionStaysIdempotent(t *testing.T) {
	e := newTestEnv(t)
	resp := e.rawPost(t, "/auth/logout", "", "", "", nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("logout with no session = %d, want 204", resp.StatusCode)
	}
}

// TestLogoutWithABadTokenIsRefused: a token that is present but wrong is a
// forgery attempt, and logout refuses it like any other guarded route. Such a
// caller is not stuck — it demonstrably holds the cookie it failed to echo.
func TestLogoutWithABadTokenIsRefused(t *testing.T) {
	e := newTestEnv(t)
	e.registerVerifyLogin(t, "csrf-logout@example.com")
	session, token := e.cookieValue("session"), e.cookieValue("csrf_token")

	cases := map[string]struct{ cookie, header string }{
		"cookie without header":        {token, ""},
		"header does not match cookie": {token, "some-other-value"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if resp := e.rawPost(t, "/auth/logout", session, c.cookie, c.header, nil); resp.StatusCode != http.StatusForbidden {
				t.Errorf("logout with %s = %d, want 403", name, resp.StatusCode)
			}
		})
	}
	// The session survived every refused logout.
	if resp := e.get(t, "/auth/me"); resp.StatusCode != http.StatusOK {
		t.Errorf("/me after refused logouts = %d, want 200", resp.StatusCode)
	}
}

// TestLogoutWithoutTheCSRFCookieStillWorks pins the escape hatch. The CSRF
// cookie is not HttpOnly, so a client can lose it on its own while keeping the
// session cookie. Under a strict guard that client would be stuck: logout is the
// only route that could end the session, and it would refuse. See
// requireCSRFUnlessTokenLost and ADR 0018.
func TestLogoutWithoutTheCSRFCookieStillWorks(t *testing.T) {
	e := newTestEnv(t)
	e.registerVerifyLogin(t, "csrf-lost@example.com")
	session := e.cookieValue("session")

	if resp := e.rawPost(t, "/auth/logout", session, "", "", nil); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("logout with a lost CSRF cookie = %d, want 204", resp.StatusCode)
	}
	// And it was a real logout, not a no-op: the session is revoked server-side.
	if resp := e.get(t, "/auth/me"); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("/me after the escape-hatch logout = %d, want 401", resp.StatusCode)
	}
}

// TestPasswordChangeWithoutTheCSRFCookieIsRefused: the hatch is logout's alone.
// A lost token must not become a way to reach a route that changes a credential.
func TestPasswordChangeWithoutTheCSRFCookieIsRefused(t *testing.T) {
	e := newTestEnv(t)
	e.registerVerifyLogin(t, "csrf-strict@example.com")
	session := e.cookieValue("session")

	if resp := e.rawPost(t, "/auth/password/change", session, "", "", changeBody()); resp.StatusCode != http.StatusForbidden {
		t.Errorf("change with a lost CSRF cookie = %d, want 403", resp.StatusCode)
	}
}

// TestCSRFCookieIsReadableAndSessionIsNot pins the two halves of the scheme: the
// CSRF cookie must be readable by JS (the frontend echoes it), the session
// cookie must not be.
func TestCSRFCookieIsReadableAndSessionIsNot(t *testing.T) {
	e := newTestEnv(t)
	if resp := e.post(t, "/auth/register", map[string]string{"email": "attrs@example.com", "password": goodPassword}); resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: %d", resp.StatusCode)
	}
	tok := e.lastToken(t)
	e.post(t, "/auth/verify-email", map[string]string{"token": tok})
	resp := e.post(t, "/auth/login", map[string]string{"email": "attrs@example.com", "password": goodPassword})

	var sessionSC, csrfSC string
	for _, sc := range resp.Header.Values("Set-Cookie") {
		switch {
		case strings.HasPrefix(sc, "session="):
			sessionSC = sc
		case strings.HasPrefix(sc, "csrf_token="):
			csrfSC = sc
		}
	}
	if csrfSC == "" {
		t.Fatal("login set no csrf_token cookie")
	}
	if strings.Contains(csrfSC, "HttpOnly") {
		t.Error("csrf_token is HttpOnly; the frontend cannot read it to echo it")
	}
	if !strings.Contains(sessionSC, "HttpOnly") {
		t.Error("session cookie lost HttpOnly")
	}
}

func TestNewRouterPanicsOnMissingCSRFKey(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("NewRouter accepted an empty CSRF key; every token would be forgeable")
		}
	}()
	_ = httpapi.NewRouter(httpapi.Deps{Limits: generousLimits()}, httpapi.Options{})
}

// --- token primitives ------------------------------------------------------

func TestCSRFTokensAreUniquePerIssue(t *testing.T) {
	const session = "a-session-token"
	seen := map[string]bool{}
	for range 100 {
		tok, err := httpapi.IssueCSRFTokenForTest(testCSRFKey, session)
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		if seen[tok] {
			t.Fatal("issued the same token twice; the nonce is not random")
		}
		seen[tok] = true
		if !httpapi.ValidCSRFTokenForTest(testCSRFKey, tok, session) {
			t.Fatal("a freshly issued token did not verify")
		}
	}
}

func TestCSRFTokenDoesNotVerifyUnderAnotherKey(t *testing.T) {
	const session = "a-session-token"
	tok, err := httpapi.IssueCSRFTokenForTest(testCSRFKey, session)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	other := []byte("a-completely-different-key-32-bytes!!")
	if httpapi.ValidCSRFTokenForTest(other, tok, session) {
		t.Error("token verified under a different server key")
	}
	if httpapi.ValidCSRFTokenForTest(testCSRFKey, tok, "a-different-session") {
		t.Error("token verified against a different session")
	}
}

// --- trusted-proxy client IP (ADR 0023) ------------------------------------

// TestClientIPResolution is the table for how the client address is derived at
// each proxy depth. The cases that matter are the fallbacks: every way the
// header can fail to deliver a trustworthy value has to land back on
// RemoteAddr, which is the hops == 0 behaviour.
func TestClientIPResolution(t *testing.T) {
	const peer = "10.0.1.5:4444" // the proxy, as far as the kernel is concerned

	cases := []struct {
		name string
		hops int
		xff  string
		want string
	}{
		{"hops 0 ignores the header entirely", 0, "1.2.3.4, 203.0.113.9", "10.0.1.5"},
		{"one proxy takes the rightmost entry", 1, "1.2.3.4, 203.0.113.9", "203.0.113.9"},
		{"two proxies take the second from the right", 2, "1.2.3.4, 203.0.113.9, 10.0.2.7", "203.0.113.9"},
		{"no header falls back to the peer", 1, "", "10.0.1.5"},
		{"fewer entries than the chain falls back", 2, "203.0.113.9", "10.0.1.5"},
		{"a non-IP entry falls back", 1, "1.2.3.4, not-an-ip", "10.0.1.5"},
		{"RFC 7239 'unknown' falls back", 1, "unknown", "10.0.1.5"},
		{"host:port entries are unwrapped", 1, "203.0.113.9:1234", "203.0.113.9"},
		{"IPv6 is preserved", 1, "1.2.3.4, 2001:db8::1", "2001:db8::1"},
		{"whitespace is tolerated", 1, "1.2.3.4 ,   203.0.113.9  ", "203.0.113.9"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
			req.RemoteAddr = peer
			if tc.xff != "" {
				req.Header.Set("X-Forwarded-For", tc.xff)
			}
			if got := httpapi.ClientIPForTest(req, tc.hops); got != tc.want {
				t.Errorf("clientIP(hops=%d, xff=%q) = %q, want %q", tc.hops, tc.xff, got, tc.want)
			}
		})
	}
}

// TestClientIPIgnoresAForgedPrefix is the security property the whole scheme
// rests on. The caller writes the left of X-Forwarded-For and can put anything
// there; only the entries the operator's own proxies appended, on the right, are
// worth reading. However much junk is prepended, the answer must not move.
func TestClientIPIgnoresAForgedPrefix(t *testing.T) {
	const real = "203.0.113.9"

	for _, forged := range []string{
		"9.9.9.9",
		"9.9.9.9, 8.8.8.8, 7.7.7.7",
		"not-an-ip, 0.0.0.0, ::1",
	} {
		req := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
		req.RemoteAddr = "10.0.1.5:4444"
		req.Header.Set("X-Forwarded-For", forged+", "+real)

		if got := httpapi.ClientIPForTest(req, 1); got != real {
			t.Errorf("with forged prefix %q: clientIP = %q, want %q", forged, got, real)
		}
	}
}

// TestClientIPJoinsRepeatedHeaderLines closes the index-shifting trick. Repeated
// header lines are semantically one comma-separated list, but Go keeps them
// apart — so a caller that sends its own X-Forwarded-For LINE, ahead of the one
// the proxy writes, would move a forged entry into the trusted position for any
// implementation that read only the first line.
func TestClientIPJoinsRepeatedHeaderLines(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	req.RemoteAddr = "10.0.1.5:4444"
	req.Header.Add("X-Forwarded-For", "9.9.9.9") // the caller's line
	req.Header.Add("X-Forwarded-For", "203.0.113.9")

	if got := httpapi.ClientIPForTest(req, 1); got != "203.0.113.9" {
		t.Errorf("clientIP = %q, want 203.0.113.9: header lines must be joined before counting", got)
	}
}

// TestIPKeySeparatesClientsBehindOneProxy is the reason the knob exists. With
// hops unset, every request through a proxy shares one key — ten logins a minute
// for the entire user base. With it set, each client gets its own bucket again.
func TestIPKeySeparatesClientsBehindOneProxy(t *testing.T) {
	req := func(xff string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
		r.RemoteAddr = "10.0.1.5:4444"
		r.Header.Set("X-Forwarded-For", xff)
		return r
	}

	collapsed := httpapi.IPKeyForTest(0)
	a, _ := collapsed(req("203.0.113.9"))
	b, _ := collapsed(req("198.51.100.4"))
	if a != b {
		t.Errorf("hops 0: keys %q and %q differ; the proxy's address is all there is to key on", a, b)
	}

	resolved := httpapi.IPKeyForTest(1)
	a, _ = resolved(req("203.0.113.9"))
	b, _ = resolved(req("198.51.100.4"))
	if a == b {
		t.Errorf("hops 1: both clients keyed to %q; each must get its own bucket", a)
	}
}

// TestRateLimitIsPerClientBehindAProxy proves the router actually wires the
// configured depth through, not just that clientIP can compute it. Every request
// arrives from the same peer; only the forwarded address tells them apart.
func TestRateLimitIsPerClientBehindAProxy(t *testing.T) {
	const limit = 2
	e := newTestEnvBehindProxies(t, tightLimits("login", limit), 1)
	const proxy = "10.0.1.5:4444"

	body := func(email string) map[string]string {
		return map[string]string{"email": email, "password": "guess"}
	}
	for i := range limit {
		if rec := e.postVia(t, proxy, "203.0.113.9", "/auth/login", body("a@example.com")); rec.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d was throttled while still under the limit", i)
		}
	}
	if rec := e.postVia(t, proxy, "203.0.113.9", "/auth/login", body("b@example.com")); rec.Code != http.StatusTooManyRequests {
		t.Errorf("over-limit request from one forwarded client = %d, want 429", rec.Code)
	}
	// A different client, same proxy, must still have its own budget.
	if rec := e.postVia(t, proxy, "198.51.100.4", "/auth/login", body("c@example.com")); rec.Code == http.StatusTooManyRequests {
		t.Error("a second client behind the same proxy was throttled by the first client's traffic")
	}
}
