package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
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

func TestIPKeyUsesRemoteAddrOnly(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	req.RemoteAddr = "198.51.100.4:5555"
	// A forged forwarding header must not change the key: a key the caller
	// controls is not a limit (ADR 0015 trusts no proxy header).
	req.Header.Set("X-Forwarded-For", "10.0.0.1")
	req.Header.Set("X-Real-IP", "10.0.0.2")

	key, ok := httpapi.IPKeyForTest(req)
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
