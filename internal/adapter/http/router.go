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
//   - forgot / resend — mail bombing a known address, spending the deployment's
//     SMTP quota and its domain's sending reputation. The per-email key is what
//     bounds how much mail one address can be made to receive, however many
//     sources ask for it.
//
// IP is checked before email: it needs no body read, so the cheap check runs
// first and a denial there costs nothing.
//
// It panics if any limiter is missing — see Limits.
func NewRouter(deps Deps, opts Options) http.Handler {
	requireLimiters(deps.Limits)
	s := &server{deps: deps, opts: opts}

	perIP := func(l port.RateLimiter) middleware { return rateLimit(l, ipKey) }
	perEmail := func(l port.RateLimiter) middleware { return rateLimit(l, emailKey) }

	mux := http.NewServeMux()
	mux.HandleFunc("POST /auth/register", chain(s.register,
		perIP(deps.Limits.Register)))
	mux.HandleFunc("POST /auth/verify-email", s.verifyEmail)
	mux.HandleFunc("POST /auth/verify-email/resend", chain(s.resendVerification,
		perIP(deps.Limits.Resend), perEmail(deps.Limits.Resend)))
	mux.HandleFunc("POST /auth/login", chain(s.login,
		perIP(deps.Limits.Login), perEmail(deps.Limits.Login)))
	mux.HandleFunc("POST /auth/logout", s.logout)
	mux.HandleFunc("GET /auth/me", s.requireAuth(s.me))
	mux.HandleFunc("POST /auth/password/change", s.requireAuth(s.changePassword))
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
