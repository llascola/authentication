package httpapi

import (
	"net/http"

	"authentication/internal/port"
)

// NewRouter builds the auth HTTP handler from the use-case dependencies and edge
// options. It uses the stdlib ServeMux with method+pattern routing (Go 1.22+) —
// no third-party router. Protected routes (/auth/me, /auth/password/change) are
// wrapped in requireAuth; the rest are public (login/logout manage the cookie
// themselves).
//
// Rate limits are declared here, next to the routes they guard, so what is
// throttled and by what key is readable in one place. Four routes are limited,
// each for a different reason:
//
//   - login — password spraying. Per-account lockout does nothing against one
//     guess each against ten thousand accounts; only the per-IP key catches
//     that. The per-email key catches the reverse, many IPs against one account.
//   - register — account-creation floods, each costing a bcrypt hash and a mail.
//     IP-keyed only: a per-email key would bound nothing here, since the address
//     is the attacker's to vary.
//   - forgot / resend — mail bombing a REGISTERED address, spending the
//     deployment's SMTP quota and its domain's sending reputation. The per-email
//     key bounds how much of that mail one registered address can be made to
//     receive, however many sources ask for it. It does not bound what a mailbox
//     receives overall: registration mails any well-formed address, and
//     subaddressing (user+1@, user+2@) gives one mailbox unlimited distinct
//     keys. See ADR 0021.
//
// IP is checked before email: it needs no body read, so the cheap check runs
// first and a denial there costs nothing.
//
// The two cookie-authenticated state-changing POSTs — password change and
// logout — additionally sit behind a CSRF guard, outside requireAuth so a forged
// request never reaches the session lookup (T29, ADR 0018). Logout is covered
// because forcing someone out is trivially preventable here, not because it is
// a breach — which is also why logout gets the relaxed guard: a client that has
// lost its CSRF cookie must still be able to end its session, since logout is
// the only route that could. The public routes need no token: no session exists
// yet, so there is no ambient authority for a cross-site request to borrow.
//
// GET /healthz sits outside /auth/ and outside all of the above: no session, no
// CSRF token, no rate limit. It is a liveness probe that does no work and
// answers everyone identically — see health.
//
// It panics if any limiter, or the CSRF key, is missing — see Limits and
// Options.CSRFKey.
func NewRouter(deps Deps, opts Options) http.Handler {
	requireLimiters(deps.Limits)
	if len(opts.CSRFKey) == 0 {
		panic("httpapi: Options.CSRFKey is required")
	}
	s := &server{deps: deps, opts: opts}

	// The IP key is bound once here, with the deployment's proxy depth, so no
	// per-request code has to consult configuration (ADR 0023).
	perIPKey := ipKey(opts.TrustedProxyHops)
	perIP := func(l port.RateLimiter) middleware { return rateLimit(l, perIPKey) }
	perEmail := func(l port.RateLimiter) middleware { return rateLimit(l, emailKey) }

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", health)
	mux.HandleFunc("POST /auth/register", chain(s.register,
		perIP(deps.Limits.Register)))
	mux.HandleFunc("POST /auth/verify-email", s.verifyEmail)
	mux.HandleFunc("POST /auth/verify-email/resend", chain(s.resendVerification,
		perIP(deps.Limits.Resend), perEmail(deps.Limits.Resend)))
	mux.HandleFunc("POST /auth/login", chain(s.login,
		perIP(deps.Limits.Login), perEmail(deps.Limits.Login)))
	mux.HandleFunc("POST /auth/logout", s.requireCSRFUnlessTokenLost(s.logout))
	mux.HandleFunc("GET /auth/me", s.requireAuth(s.me))
	mux.HandleFunc("POST /auth/password/change", s.requireCSRF(s.requireAuth(s.changePassword)))
	mux.HandleFunc("POST /auth/password/forgot", chain(s.forgotPassword,
		perIP(deps.Limits.Forgot), perEmail(deps.Limits.Forgot)))
	mux.HandleFunc("POST /auth/password/reset", s.resetPassword)
	return mux
}

// requireLimiters fails the build of the router rather than serving a route
// with no throttle on it.
func requireLimiters(l Limits) {
	for name, limiter := range map[string]port.RateLimiter{
		"Login":    l.Login,
		"Register": l.Register,
		"Forgot":   l.Forgot,
		"Resend":   l.Resend,
	} {
		if limiter == nil {
			panic("httpapi: Deps.Limits." + name + " is required")
		}
	}
}
