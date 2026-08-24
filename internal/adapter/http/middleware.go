// Package httpapi is the driving HTTP edge over the application use-cases. It is
// deliberately thin: each handler decodes a request, calls one use-case, and
// encodes a response. No domain logic lives here. The error→status map
// (errors.go) is the single audited place enumeration safety is enforced.
package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"strconv"
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

// ipKey keys a limiter by the peer address of the connection.
//
// RemoteAddr only: no X-Forwarded-For, no X-Real-IP (ADR 0015 trusts no proxy
// header). A key an attacker can set is not a limit — one header line per
// request would give them a fresh bucket every time. If a reverse proxy is put
// in front of this server, trusting its forwarding header becomes a deliberate,
// ADR-recorded change, not an accident.
func ipKey(r *http.Request) (string, bool) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// Not host:port (a unix socket, say). The raw value still identifies the
		// peer, which is all a key has to do.
		host = r.RemoteAddr
	}
	if host == "" {
		return "", false
	}
	return "ip:" + host, true
}

// emailKey keys a limiter by the email in the request body, canonicalised
// through domain.NewEmail — the same trim-and-lowercase the use-cases apply, so
// "User@x.com" and "user@x.com" cannot buy two budgets for one address.
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
