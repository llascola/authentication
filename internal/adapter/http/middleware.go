// Package httpapi is the driving HTTP edge over the application use-cases. It is
// deliberately thin: each handler decodes a request, calls one use-case, and
// encodes a response. No domain logic lives here. The error→status map
// (errors.go) is the single audited place enumeration safety is enforced.
package httpapi

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"authentication/internal/app"
	"authentication/internal/domain"
	"authentication/internal/port"
)

type ctxKey int

const identityKey ctxKey = iota

// requireAuth wraps a handler so it runs only for a request carrying a valid
// session cookie. It resolves the cookie through ValidateSession (which slides
// the idle window) and injects the authenticated Identity into the request
// context. Any failure — missing cookie, unknown/revoked/expired session —
// yields a single 401 with no detail.
func (s *server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(cookieName)
		if err != nil {
			writeError(w, r, app.ErrNotAuthenticated)
			return
		}
		id, err := s.deps.ValidateSession.Validate(r.Context(), c.Value)
		if err != nil {
			writeError(w, r, app.ErrNotAuthenticated)
			return
		}
		ctx := context.WithValue(r.Context(), identityKey, id)
		next(w, r.WithContext(ctx))
	}
}

// identityFrom returns the authenticated Identity placed by requireAuth. The ok
// result is false on an unauthenticated request (a programming error if reached
// from behind requireAuth).
func identityFrom(ctx context.Context) (app.Identity, bool) {
	id, ok := ctx.Value(identityKey).(app.Identity)
	return id, ok
}

// --- rate limiting ---------------------------------------------------------

// limiterOutageRetryAfter is what a client is told to wait when the limiter
// itself failed. The window it would normally report is unknowable in that
// case, so this is a deliberately short, fixed guess: long enough not to
// hammer, short enough that a brief outage is not felt as an outage.
const limiterOutageRetryAfter = 5 * time.Second

// middleware is a handler decorator. chain composes them outermost-first.
type middleware func(http.HandlerFunc) http.HandlerFunc

func chain(h http.HandlerFunc, mw ...middleware) http.HandlerFunc {
	for i := len(mw) - 1; i >= 0; i-- {
		h = mw[i](h)
	}
	return h
}

// keyFunc derives a rate-limit key from a request. ok is false when the request
// carries nothing to key on — a body that is missing, oversized, unparseable,
// or holds no usable email. Such a request is passed through untouched by THIS
// limiter; it is still subject to the others in the chain (every protected
// route is keyed by IP as well), and the handler will reject it on its own
// terms. Guessing a key would be worse: a fallback shared by all unparseable
// requests is a bucket one client can exhaust for everyone.
type keyFunc func(*http.Request) (string, bool)

// rateLimit rejects a request whose key is over its limiter's budget with a 429
// and a Retry-After header.
//
// The check runs before the handler, so a denied request costs no bcrypt
// comparison, no repository lookup, and no mail. It also runs before anything
// looks the account up, which is what keeps the limiter from becoming an
// account-existence oracle: the key is derived from the SUBMITTED value alone,
// so an address that was never registered is throttled exactly like one that
// was.
//
// On limiter failure the request is REJECTED (503), not allowed through. The
// alternative — fail open — hands an attacker who can break the limiter the
// ability to switch off every throttle in the process, which is precisely when
// the throttle matters. The cost is that a limiter outage is an auth outage;
// with the in-process limiter that cannot happen at all, since it never fails.
func rateLimit(limiter port.RateLimiter, key keyFunc) middleware {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			k, ok := key(r)
			if !ok {
				next(w, r)
				return
			}
			allowed, retryAfter, err := limiter.Allow(r.Context(), k)
			switch {
			case err != nil:
				slog.Error("rate limiter unavailable", "path", r.URL.Path, "err", err)
				setRetryAfter(w, limiterOutageRetryAfter)
				writeError(w, r, errLimiterUnavailable)
			case !allowed:
				setRetryAfter(w, retryAfter)
				writeError(w, r, errRateLimited)
			default:
				next(w, r)
			}
		}
	}
}

// setRetryAfter writes the header in its delta-seconds form, rounded up and
// never below one second — a Retry-After of 0 invites an immediate retry that
// is certain to be refused. The value describes the limiter, not the account,
// so it leaks nothing.
func setRetryAfter(w http.ResponseWriter, d time.Duration) {
	seconds := int64(math.Ceil(d.Seconds()))
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
}

// ipKey builds a limiter key from the client address, resolved per the
// deployment's trusted-proxy setting (ADR 0023).
//
// It is a factory rather than a plain keyFunc because hops is deployment
// configuration: the router binds it once at wiring time, so no per-request code
// has to reach for config.
func ipKey(hops int) keyFunc {
	return func(r *http.Request) (string, bool) {
		host := clientIP(r, hops)
		if host == "" {
			return "", false
		}
		return "ip:" + host, true
	}
}

// clientIP resolves who is calling, and is the ONE place that question is
// answered — the rate limiter and the session's DeviceInfo must not disagree
// about it.
//
// hops <= 0 (the default) is RemoteAddr and nothing else: no X-Forwarded-For, no
// X-Real-IP. A key an attacker can set is not a limit, and every forwarding
// header is attacker-settable by default — one extra header line per request
// would otherwise buy a fresh rate-limit bucket every time. This is the posture
// ADR 0015 locked.
//
// hops > 0 says the operator runs exactly that many proxies in front of this
// server, so the last hops entries of X-Forwarded-For were written by their
// infrastructure rather than by the caller. The value taken is the hops'th from
// the RIGHT: everything to its left is the client's to forge and is ignored.
// ADR 0023 and the block comment in internal/config carry the reasoning and the
// network assumption this rests on.
//
// Every way the header can fail to deliver a usable address — absent, too few
// entries for the configured chain, an entry that is not an IP — falls back to
// RemoteAddr. That is the safe direction: a request that did not arrive the way
// the configuration claims is treated as if the header were not trusted at all,
// which is exactly the hops == 0 behaviour.
func clientIP(r *http.Request, hops int) string {
	if hops > 0 {
		if ip := forwardedFor(r, hops); ip != "" {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// Not host:port (a unix socket, say). The raw value still identifies the
		// peer, which is all a key has to do.
		host = r.RemoteAddr
	}
	return host
}

// forwardedFor returns the hops'th X-Forwarded-For entry counted from the right,
// or "" if there is no trustworthy one.
//
// It joins every X-Forwarded-For header LINE before splitting, because repeated
// header lines are semantically one comma-separated list and Go keeps them
// apart. Reading only the first line would let a caller send a second line to
// shift the indices and move a forged entry into the trusted position.
//
// The result must parse as an IP. A proxy that writes something else — a
// hostname, an obfuscated identifier, "unknown" per RFC 7239 — yields no answer
// rather than a key built from an arbitrary string.
func forwardedFor(r *http.Request, hops int) string {
	values := r.Header.Values("X-Forwarded-For")
	if len(values) == 0 {
		return ""
	}
	parts := strings.Split(strings.Join(values, ","), ",")
	i := len(parts) - hops
	if i < 0 {
		// Fewer entries than the configured chain: this request did not traverse
		// the proxies the operator described, so nothing here is trustworthy.
		return ""
	}
	candidate := strings.TrimSpace(parts[i])
	if candidate == "" {
		return ""
	}
	// Some proxies write host:port, and IPv6 arrives bracketed.
	if host, _, err := net.SplitHostPort(candidate); err == nil {
		candidate = host
	}
	if net.ParseIP(candidate) == nil {
		return ""
	}
	return candidate
}

// emailKey keys a limiter by the email in the request body, canonicalised
// through domain.NewEmail — the same trim-and-lowercase the use-cases apply, so
// "User@x.com" and "user@x.com" cannot buy two budgets for one address.
//
// Canonicalisation stops there. Provider-specific aliasing — subaddressing
// ("user+1@"), Gmail's dot-folding — yields a distinct key per variant for what
// may be one mailbox, and is deliberately not undone: the rules differ per
// provider, and folding them would merge genuinely distinct addresses into a
// shared bucket, which is its own denial of service. ADR 0021 records what that
// leaves unbounded.
//
// It reads the body and puts it back, because the handler still has to decode
// it. The read is bounded by the same maxBodyBytes the handler enforces, and an
// oversized body yields no key: the handler's own MaxBytesReader will reject it
// a moment later.
//
// A malformed or absent email yields no key, so such a request is only
// IP-limited. That is not a bypass worth closing — the handler rejects it
// without touching the account store or the mailer, which is the cost this
// limiter exists to bound.
func emailKey(r *http.Request) (string, bool) {
	if r.Body == nil {
		return "", false
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil {
		return "", false
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	if len(raw) > maxBodyBytes {
		return "", false
	}

	var in emailOnly
	if err := json.Unmarshal(raw, &in); err != nil {
		return "", false
	}
	email, err := domain.NewEmail(in.Email)
	if err != nil {
		return "", false
	}
	return "email:" + email.String(), true
}

// --- CSRF ------------------------------------------------------------------

// The CSRF scheme is double-submit with the token bound to the session by an
// HMAC (ADR 0018).
//
// A plain double-submit token proves only that whoever sent the request could
// also set a cookie on this domain. Any subdomain can do that, so an unbound
// token is defeated by exactly the same-site attacker SameSite=Lax already
// fails against — which would leave the mitigation and the defence sharing one
// weakness. Binding the token to the session token with a server-held key
// closes that: forging a token for someone else's session needs the key.
//
// Token layout: base64url(nonce) "." base64url(HMAC-SHA256(key, nonce|session)).
// The nonce lets the server hand out a fresh token for a session that is staying
// put — needed because ADR 0017 keeps the session alive across a password
// change, so a token derived from the session alone could never change without
// logging the user out.
//
// KNOWN LIMITATION: verification is stateless, so issuing a new token does not
// invalidate an old one. Every token ever minted for a live session keeps
// verifying until that session ends. Revoking one would need per-session state
// or a re-keyed session bearer token — see ADR 0018 and the test named
// TestCSRFOldTokenStillVerifiesAfterRotation, which pins the current behaviour.
//
// The CSRF cookie is deliberately readable by JavaScript: the frontend has to
// echo it in a header, and a header is the part a cross-site form post cannot
// forge. It carries no authority alone — the session cookie stays HttpOnly.
const (
	csrfCookieName = "csrf_token"
	csrfHeaderName = "X-CSRF-Token"
	csrfNonceBytes = 16
)

// issueCSRFToken mints a fresh token bound to the given raw session token. A new
// call yields a new nonce, so this doubles as the rotation primitive.
func issueCSRFToken(key []byte, sessionRaw string) (string, error) {
	nonce := make([]byte, csrfNonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(nonce) + "." +
		base64.RawURLEncoding.EncodeToString(csrfMAC(key, nonce, sessionRaw)), nil
}

func csrfMAC(key, nonce []byte, sessionRaw string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(nonce)
	m.Write([]byte{'|'}) // separator: nonce is fixed-length, but be explicit
	m.Write([]byte(sessionRaw))
	return m.Sum(nil)
}

// validCSRFToken reports whether presented is a token this server minted for
// this session. hmac.Equal is constant-time.
func validCSRFToken(key []byte, presented, sessionRaw string) bool {
	noncePart, macPart, ok := strings.Cut(presented, ".")
	if !ok {
		return false
	}
	nonce, err := base64.RawURLEncoding.DecodeString(noncePart)
	if err != nil || len(nonce) != csrfNonceBytes {
		return false
	}
	mac, err := base64.RawURLEncoding.DecodeString(macPart)
	if err != nil {
		return false
	}
	return hmac.Equal(mac, csrfMAC(key, nonce, sessionRaw))
}

// requireCSRF rejects a cookie-authenticated state-changing request that does
// not carry a matching, session-bound CSRF token.
func (s *server) requireCSRF(next http.HandlerFunc) http.HandlerFunc {
	return s.csrfGuard(next, false)
}

// requireCSRFUnlessTokenLost is requireCSRF with one escape hatch: a request
// whose CSRF COOKIE is absent entirely passes through instead of being refused.
//
// It exists for logout, and only for logout. Under the strict guard a client
// holding a session cookie but no CSRF cookie is stuck: every state-changing
// route refuses it, including the one route that would clear the session. Since
// the CSRF cookie is deliberately not HttpOnly, it is the one an extension, a
// partial cookie clear, or a privacy tool can plausibly drop on its own, leaving
// a live session with no way out until it expires.
//
// What this gives up: a same-site attacker who can delete the CSRF cookie on the
// parent domain can then force a logout. That is the outcome ADR 0018 already
// judged worth little — "forcing someone out is trivially preventable here, not
// because it is a breach" — and a self-inflicted lockout is the more likely
// event. A cross-site attacker gains nothing: SameSite=Lax means a cross-site
// POST carries no session cookie either, so it takes the no-session path below
// and logout no-ops as it always did.
//
// The hatch is only for a MISSING cookie. A cookie that is present but does not
// match, or is not bound to this session, is still a 403 — that is a forgery
// attempt, not a lost token, and such a client can recover by echoing the cookie
// it demonstrably has.
func (s *server) requireCSRFUnlessTokenLost(next http.HandlerFunc) http.HandlerFunc {
	return s.csrfGuard(next, true)
}

// csrfGuard is the one implementation behind both wrappers.
//
// A request with no session cookie passes straight through: there is no ambient
// authority to abuse, and the handler behind it decides what to do (401 for a
// protected route, a no-op 204 for logout). Requiring a token there would break
// logout's idempotence without protecting anything.
//
// It runs OUTSIDE requireAuth so a forged request is refused before the session
// lookup, and — more to the point — before ValidateSession slides that session's
// idle window. An attacker should not be able to keep a victim's session alive
// with forged requests.
func (s *server) csrfGuard(next http.HandlerFunc, allowMissingCookie bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := r.Cookie(cookieName)
		if err != nil {
			next(w, r)
			return
		}
		cookie, err := r.Cookie(csrfCookieName)
		if err != nil {
			if allowMissingCookie {
				next(w, r)
				return
			}
			writeError(w, r, errCSRF)
			return
		}
		header := r.Header.Get(csrfHeaderName)
		if header == "" {
			writeError(w, r, errCSRF)
			return
		}
		// Double-submit: the header must equal the cookie. A cross-site caller
		// can make the browser send the cookie but cannot read it to echo it.
		if subtle.ConstantTimeCompare([]byte(header), []byte(cookie.Value)) != 1 {
			writeError(w, r, errCSRF)
			return
		}
		// Binding: and the token must be one WE minted for THIS session, which
		// is what a same-site attacker who can set cookies cannot fake.
		if !validCSRFToken(s.opts.CSRFKey, header, session.Value) {
			writeError(w, r, errCSRF)
			return
		}
		next(w, r)
	}
}
