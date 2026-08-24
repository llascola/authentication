package httpapi

import (
	"encoding/json"
	"net"
	"net/http"
	"time"

	"authentication/internal/app"
	"authentication/internal/domain"
	"authentication/internal/port"
)

const (
	cookieName   = "session"
	maxBodyBytes = 64 << 10 // 64 KiB: auth payloads are tiny
)

// Limits are the rate limiters guarding the routes an attacker can turn into
// something expensive. One limiter per route rather than one shared instance:
// a login attempt must not spend the budget a password-reset mail needs.
//
// Every field is required. NewRouter panics on a missing one — a route that
// silently ships unthrottled is the failure mode this whole task exists to
// prevent, and a nil check at wiring time is cheaper than discovering it from
// an SMTP bill.
type Limits struct {
	Login    port.RateLimiter
	Register port.RateLimiter
	Forgot   port.RateLimiter
	Resend   port.RateLimiter
}

// Deps are the driven dependencies the HTTP edge holds: the use-case services
// it calls, and the edge-level ports (rate limiters) it enforces itself.
type Deps struct {
	Limits Limits

	Register           *app.RegisterService
	VerifyEmail        *app.VerifyEmailService
	ResendVerification *app.ResendVerificationService
	Login              *app.LoginService
	ValidateSession    *app.ValidateSessionService
	Logout             *app.LogoutService
	ChangePassword     *app.ChangePasswordService
	ForgotPassword     *app.ForgotPasswordService
	ResetPassword      *app.ResetPasswordService
}

// Options are edge-level settings sourced from config.
type Options struct {
	CookieSecure bool          // Secure attribute on the session cookie
	SessionTTL   time.Duration // cookie Max-Age (the absolute session lifetime)

	// CSRFKey is the server secret CSRF tokens are HMAC'd with. Required:
	// NewRouter panics on an empty one, because an empty key makes every token
	// forgeable by anyone who reads this source.
	CSRFKey []byte
}

type server struct {
	deps Deps
	opts Options
}

// --- JSON + cookie helpers -------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if body != nil {
		_ = json.NewEncoder(w).Encode(body)
	}
}

// decodeJSON reads a size-limited JSON body into dst. A malformed or oversized
// body is a client error.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

// setSessionCookie installs the session bearer token. HttpOnly keeps it away
// from JS; Secure confines it to HTTPS (configurable off for local http);
// SameSite=Lax blunts CSRF on cross-site POSTs while allowing top-level GETs.
func (s *server) setSessionCookie(w http.ResponseWriter, raw string) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    raw,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.opts.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(s.opts.SessionTTL.Seconds()),
	})
}

// setCSRFCookie mints a CSRF token bound to the given raw session token and
// installs it. Deliberately NOT HttpOnly: the frontend must read it to echo it
// in the X-CSRF-Token header, and that header is the part a cross-site form
// post cannot produce. The cookie grants nothing on its own.
//
// Calling this again for a live session hands the client a new token (the nonce
// changes). It does NOT invalidate the previous one — verification is stateless.
// See the limitation note in middleware.go and ADR 0018.
func (s *server) setCSRFCookie(w http.ResponseWriter, sessionRaw string) error {
	token, err := issueCSRFToken(s.opts.CSRFKey, sessionRaw)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: false,
		Secure:   s.opts.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(s.opts.SessionTTL.Seconds()),
	})
	return nil
}

func (s *server) clearCSRFCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: false,
		Secure:   s.opts.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

func (s *server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.opts.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// deviceFromRequest builds DeviceInfo from the connection. No proxy headers are
// trusted for the slice. A RemoteAddr without a parseable host yields an empty
// IP, which DeviceInfo accepts.
func deviceFromRequest(r *http.Request) domain.DeviceInfo {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = ""
	}
	d, _ := domain.NewDeviceInfo(host, r.UserAgent(), "")
	return d
}

// --- handlers --------------------------------------------------------------

type credentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// register: POST /auth/register. Always 201 on a well-formed request, whether
// the email is new or already taken (the use-case hides duplicates), so the
// response cannot be used to probe which addresses exist.
func (s *server) register(w http.ResponseWriter, r *http.Request) {
	var in credentials
	if err := decodeJSON(w, r, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed request"})
		return
	}
	if err := s.deps.Register.Register(r.Context(), in.Email, in.Password); err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"status": "verification_sent"})
}

// resendVerification: POST /auth/verify-email/resend. Public by design — the
// caller cannot log in yet, which is the whole reason the route exists. Always
// 202 with the same body, whether the address is unregistered, already
// verified, or genuinely pending, so it cannot be used to probe account state.
func (s *server) resendVerification(w http.ResponseWriter, r *http.Request) {
	var in emailOnly
	if err := decodeJSON(w, r, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed request"})
		return
	}
	if err := s.deps.ResendVerification.ResendVerification(r.Context(), in.Email); err != nil {
		writeError(w, r, err) // only infra faults reach here
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "verification_sent"})
}

type tokenOnly struct {
	Token string `json:"token"`
}

// verifyEmail: POST /auth/verify-email.
func (s *server) verifyEmail(w http.ResponseWriter, r *http.Request) {
	var in tokenOnly
	if err := decodeJSON(w, r, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed request"})
		return
	}
	if err := s.deps.VerifyEmail.VerifyEmail(r.Context(), in.Token); err != nil {
		writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// login: POST /auth/login. On success sets the session cookie; every failure is
// an identical 401.
func (s *server) login(w http.ResponseWriter, r *http.Request) {
	var in credentials
	if err := decodeJSON(w, r, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed request"})
		return
	}
	raw, err := s.deps.Login.Login(r.Context(), in.Email, in.Password, deviceFromRequest(r))
	if err != nil {
		writeError(w, r, err)
		return
	}
	s.setSessionCookie(w, raw)
	// A fresh session gets a fresh CSRF token bound to it.
	if err := s.setCSRFCookie(w, raw); err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// logout: POST /auth/logout. Idempotent; always clears the cookie and returns
// 204, whether or not a valid session was presented.
func (s *server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		_ = s.deps.Logout.Logout(r.Context(), c.Value)
	}
	s.clearSessionCookie(w)
	s.clearCSRFCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

// me: GET /auth/me. Behind requireAuth; reports the authenticated identity.
func (s *server) me(w http.ResponseWriter, r *http.Request) {
	id, ok := identityFrom(r.Context())
	if !ok {
		writeError(w, r, app.ErrNotAuthenticated)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user_id":    id.UserID.String(),
		"auth_level": id.AuthLevel.String(),
	})
}

type changePasswordInput struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

// changePassword: POST /auth/password/change. Behind requireAuth.
func (s *server) changePassword(w http.ResponseWriter, r *http.Request) {
	id, ok := identityFrom(r.Context())
	if !ok {
		writeError(w, r, app.ErrNotAuthenticated)
		return
	}
	var in changePasswordInput
	if err := decodeJSON(w, r, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed request"})
		return
	}
	// The whole Identity, not just the user id: it carries the calling session's
	// stored hash, which is how that session survives the change (ADR 0017).
	if err := s.deps.ChangePassword.ChangePassword(r.Context(), id, in.OldPassword, in.NewPassword); err != nil {
		writeError(w, r, err)
		return
	}
	// The session survives the change (ADR 0017), so its CSRF token has to be
	// rotated rather than carried over: a token minted under the old credential
	// must not outlive it. This is the obligation ADR 0017 recorded.
	if c, err := r.Cookie(cookieName); err == nil {
		if err := s.setCSRFCookie(w, c.Value); err != nil {
			writeError(w, r, err)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

type emailOnly struct {
	Email string `json:"email"`
}

// forgotPassword: POST /auth/password/forgot. Always 202, regardless of whether
// the email is registered.
func (s *server) forgotPassword(w http.ResponseWriter, r *http.Request) {
	var in emailOnly
	if err := decodeJSON(w, r, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed request"})
		return
	}
	if err := s.deps.ForgotPassword.ForgotPassword(r.Context(), in.Email); err != nil {
		writeError(w, r, err) // only infra faults reach here
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "reset_sent"})
}

type resetPasswordInput struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

// resetPassword: POST /auth/password/reset.
func (s *server) resetPassword(w http.ResponseWriter, r *http.Request) {
	var in resetPasswordInput
	if err := decodeJSON(w, r, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed request"})
		return
	}
	if err := s.deps.ResetPassword.ResetPassword(r.Context(), in.Token, in.NewPassword); err != nil {
		writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
