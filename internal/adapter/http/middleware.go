// Package httpapi is the driving HTTP edge over the application use-cases. It is
// deliberately thin: each handler decodes a request, calls one use-case, and
// encodes a response. No domain logic lives here. The error→status map
// (errors.go) is the single audited place enumeration safety is enforced.
package httpapi

import (
	"context"
	"net/http"

	"authentication/internal/app"
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
