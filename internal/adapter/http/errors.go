package httpapi

import (
	"errors"
	"log/slog"
	"net/http"

	"authentication/internal/app"
	"authentication/internal/domain"
	"authentication/internal/port"
)

// Edge-only errors. These never come from the application — they describe what
// happened at the HTTP boundary — but they are routed through writeError so
// every status this server can emit is assigned in one auditable place.
var (
	// errRateLimited: the caller is over the budget for its key (T28).
	errRateLimited = errors.New("httpapi: rate limit exceeded")
	// errLimiterUnavailable: the limiter itself failed, so the request was
	// refused rather than waved through (see rateLimit in middleware.go).
	errLimiterUnavailable = errors.New("httpapi: rate limiter unavailable")
	// errCSRF: a cookie-authenticated state-changing request carried a missing,
	// mismatched, or wrongly-bound CSRF token (T29).
	errCSRF = errors.New("httpapi: csrf token missing or invalid")
)

// writeError maps an application/domain error to an HTTP status and a generic
// body. This is the one place statuses are assigned, so enumeration safety is
// auditable here:
//
//   - ErrAuthFailed / ErrNotAuthenticated → 401 with a fixed body, so "no such
//     account", "wrong password", "locked", and "no session" are all identical.
//   - ErrInvalidToken → 400, identical for unknown/expired/consumed/wrong-purpose.
//   - errCSRF → 403 with a fixed body. It says nothing about which of "no
//     token", "wrong token", or "another session's token" happened.
//   - errRateLimited → 429 with a fixed body, identical whether or not the
//     account exists; errLimiterUnavailable → 503. Both are set alongside a
//     Retry-After header by the middleware that raises them.
//   - Password-policy and malformed-input errors → 400 with the (input-only,
//     non-sensitive) reason, since they describe the submitted values.
//   - Anything else is an unexpected server fault → 500, logged, body hidden.
//
// Note: enumeration-sensitive flows (register duplicate-email, forgot-password
// unknown-email) never reach here with a revealing error — the use-cases return
// nil for those, so the handler emits its normal success response.
func writeError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, app.ErrAuthFailed), errors.Is(err, app.ErrNotAuthenticated):
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	case errors.Is(err, app.ErrInvalidToken):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid or expired token"})
	case errors.Is(err, errCSRF):
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
	case errors.Is(err, errRateLimited):
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many requests"})
	case errors.Is(err, errLimiterUnavailable):
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "service unavailable"})
	case isInputError(err):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
	default:
		slog.Error("unhandled server error", "method", r.Method, "path", r.URL.Path, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
	}
}

// isInputError reports whether err is a client input-validation error safe to
// surface verbatim: a password-policy violation or a malformed value
// (email/phone/etc.). These concern the submitted payload, not account state.
func isInputError(err error) bool {
	for _, sentinel := range []error{
		domain.ErrPasswordTooShort,
		domain.ErrPasswordTooLong,
		domain.ErrPasswordNoUpper,
		domain.ErrPasswordNoLower,
		domain.ErrPasswordNoDigit,
		domain.ErrPasswordNoSymbol,
	} {
		if errors.Is(err, sentinel) {
			return true
		}
	}
	// Breach-screen rejection is also a client-correctable input error.
	if errors.Is(err, port.ErrPasswordBreached) {
		return true
	}
	return errors.Is(err, domain.ErrInvalidEmail)
}
