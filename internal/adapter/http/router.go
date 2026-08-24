package httpapi

import "net/http"

// NewRouter builds the auth HTTP handler from the use-case dependencies and edge
// options. It uses the stdlib ServeMux with method+pattern routing (Go 1.22+) —
// no third-party router. Protected routes (/auth/me, /auth/password/change) are
// wrapped in requireAuth; the rest are public (login/logout manage the cookie
// themselves).
func NewRouter(deps Deps, opts Options) http.Handler {
	s := &server{deps: deps, opts: opts}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /auth/register", s.register)
	mux.HandleFunc("POST /auth/verify-email", s.verifyEmail)
	mux.HandleFunc("POST /auth/verify-email/resend", s.resendVerification)
	mux.HandleFunc("POST /auth/login", s.login)
	mux.HandleFunc("POST /auth/logout", s.logout)
	mux.HandleFunc("GET /auth/me", s.requireAuth(s.me))
	mux.HandleFunc("POST /auth/password/change", s.requireAuth(s.changePassword))
	mux.HandleFunc("POST /auth/password/forgot", s.forgotPassword)
	mux.HandleFunc("POST /auth/password/reset", s.resetPassword)
	return mux
}
