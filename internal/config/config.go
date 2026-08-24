// Package config loads server configuration from the environment with sane
// defaults. No external config library — stdlib os/strconv/time only.
package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// bcrypt cost bounds, mirrored from golang.org/x/crypto/bcrypt so this package
// need not import it (x/crypto stays confined to adapter/crypto). Keep in sync
// with bcrypt.MinCost / bcrypt.MaxCost.
const (
	minBcryptCost = 4
	maxBcryptCost = 31
)

// Breach-screener choices. ScreenerNoOp accepts everything and is the default so
// an offline CI run and a fresh checkout both work; ScreenerHIBP queries the
// Pwned Passwords range API.
const (
	ScreenerNoOp = "noop"
	ScreenerHIBP = "hibp"
)

// minCSRFKeyBytes is the floor for AUTH_CSRF_KEY. The token is an HMAC-SHA256,
// whose security rests entirely on this key being unguessable; 32 bytes matches
// the hash's block-relevant size and rules out a short passphrase being pasted
// in by mistake.
const minCSRFKeyBytes = 32

// RateLimitPolicy is one route's throttle: Limit actions per Window, per key.
// The edge decides what a key is (client IP, submitted email); this only
// carries the numbers.
type RateLimitPolicy struct {
	Limit  int
	Window time.Duration
}

// Config is the resolved server configuration.
type Config struct {
	ListenAddr   string
	IdleTTL      time.Duration
	AbsTTL       time.Duration
	BcryptCost   int
	CookieSecure bool

	// CSRFKey is the server secret the CSRF token is HMAC'd with. Empty means
	// unset: the composition root generates an ephemeral one and warns, which is
	// fine while sessions are in-memory (a restart drops both) and must not
	// survive into Phase 07, where sessions outlive the process.
	CSRFKey []byte

	// Rate limits, one policy per protected route. Defaults are chosen so a
	// real person never meets them: someone mistyping a password a few times,
	// or asking for a second verification mail, must not be locked out.
	LoginRate    RateLimitPolicy
	RegisterRate RateLimitPolicy
	ForgotRate   RateLimitPolicy
	ResendRate   RateLimitPolicy

	// Breach screening. Screener selects the implementation; the default keeps
	// dev and CI offline, so `make check` never touches the network.
	Screener         string
	ScreenerTimeout  time.Duration
	ScreenerFailOpen bool

	// Mailer. When SMTPAddr is empty the process wires the dev-only LogMailer;
	// when set, all other mailer fields are required and an SmtpMailer is used.
	SMTPAddr      string
	SMTPUser      string
	SMTPPass      string
	MailFrom      string
	VerifyURLBase string
	ResetURLBase  string
}

// SMTPEnabled reports whether a real SMTP mailer is configured. When false the
// composition root falls back to the dev-only LogMailer.
func (c Config) SMTPEnabled() bool { return c.SMTPAddr != "" }

// Defaults applied when an env var is unset.
const (
	defaultListenAddr = ":8080"
	defaultIdleTTL    = 30 * time.Minute
	defaultAbsTTL     = 24 * time.Hour
	defaultBcryptCost = 10 // bcrypt.DefaultCost

	// defaultScreener keeps a fresh checkout and CI offline. Turning on the real
	// screen is a deliberate deployment act (AUTH_PASSWORD_SCREENER=hibp).
	defaultScreener = ScreenerNoOp
	// defaultScreenerTimeout bounds a third party's latency on the registration
	// path. Short enough that an outage degrades rather than hangs.
	defaultScreenerTimeout = 3 * time.Second
	// defaultScreenerFailOpen: an unreachable corpus accepts the password. See
	// screener.FailOpen and ADR 0019 for the trade.
	defaultScreenerFailOpen = true
)

// Default rate limits. Each applies per key, and every protected route is keyed
// by client IP; login, forgot, and resend are additionally keyed by the
// submitted email.
//
// Login is per-minute because a human retries a mistyped password within
// seconds and gives up quickly, while a spray needs sustained volume. The
// mail-sending routes are per-hour because their cost is not CPU but an actual
// email: five is generous for a person, and a hard ceiling on how much mail one
// address can be made to receive.
//
// These are per-process (the in-memory limiter). N replicas mean N times these
// numbers until a shared backend replaces it.
var (
	defaultLoginRate    = RateLimitPolicy{Limit: 10, Window: time.Minute}
	defaultRegisterRate = RateLimitPolicy{Limit: 10, Window: time.Hour}
	defaultForgotRate   = RateLimitPolicy{Limit: 5, Window: time.Hour}
	defaultResendRate   = RateLimitPolicy{Limit: 5, Window: time.Hour}
)

// Load reads configuration from the environment, applying defaults for unset
// values and rejecting malformed or out-of-range ones.
func Load() (Config, error) {
	cfg := Config{
		ListenAddr:       defaultListenAddr,
		IdleTTL:          defaultIdleTTL,
		AbsTTL:           defaultAbsTTL,
		BcryptCost:       defaultBcryptCost,
		CookieSecure:     true,
		Screener:         defaultScreener,
		ScreenerTimeout:  defaultScreenerTimeout,
		ScreenerFailOpen: defaultScreenerFailOpen,
		LoginRate:        defaultLoginRate,
		RegisterRate:     defaultRegisterRate,
		ForgotRate:       defaultForgotRate,
		ResendRate:       defaultResendRate,
	}

	if v := os.Getenv("AUTH_LISTEN_ADDR"); v != "" {
		cfg.ListenAddr = v
	}

	var err error
	if cfg.IdleTTL, err = durationEnv("AUTH_SESSION_IDLE_TTL", cfg.IdleTTL); err != nil {
		return Config{}, err
	}
	if cfg.AbsTTL, err = durationEnv("AUTH_SESSION_ABS_TTL", cfg.AbsTTL); err != nil {
		return Config{}, err
	}
	if cfg.BcryptCost, err = intEnv("AUTH_BCRYPT_COST", cfg.BcryptCost); err != nil {
		return Config{}, err
	}
	if cfg.CookieSecure, err = boolEnv("AUTH_COOKIE_SECURE", cfg.CookieSecure); err != nil {
		return Config{}, err
	}

	for _, p := range []struct {
		prefix string
		dst    *RateLimitPolicy
	}{
		{"AUTH_RATELIMIT_LOGIN", &cfg.LoginRate},
		{"AUTH_RATELIMIT_REGISTER", &cfg.RegisterRate},
		{"AUTH_RATELIMIT_FORGOT", &cfg.ForgotRate},
		{"AUTH_RATELIMIT_RESEND", &cfg.ResendRate},
	} {
		if *p.dst, err = rateLimitEnv(p.prefix, *p.dst); err != nil {
			return Config{}, err
		}
	}

	if v := os.Getenv("AUTH_PASSWORD_SCREENER"); v != "" {
		cfg.Screener = v
	}
	if cfg.Screener != ScreenerNoOp && cfg.Screener != ScreenerHIBP {
		return Config{}, fmt.Errorf("config: AUTH_PASSWORD_SCREENER must be %q or %q, got %q",
			ScreenerNoOp, ScreenerHIBP, cfg.Screener)
	}
	if cfg.ScreenerTimeout, err = durationEnv("AUTH_SCREENER_TIMEOUT", cfg.ScreenerTimeout); err != nil {
		return Config{}, err
	}
	if cfg.ScreenerTimeout <= 0 {
		return Config{}, fmt.Errorf("config: AUTH_SCREENER_TIMEOUT must be positive, got %s", cfg.ScreenerTimeout)
	}
	if cfg.ScreenerFailOpen, err = boolEnv("AUTH_SCREENER_FAIL_OPEN", cfg.ScreenerFailOpen); err != nil {
		return Config{}, err
	}

	if v := os.Getenv("AUTH_CSRF_KEY"); v != "" {
		if len(v) < minCSRFKeyBytes {
			return Config{}, fmt.Errorf("config: AUTH_CSRF_KEY must be at least %d bytes, got %d", minCSRFKeyBytes, len(v))
		}
		cfg.CSRFKey = []byte(v)
	}

	cfg.SMTPAddr = os.Getenv("AUTH_SMTP_ADDR")
	cfg.SMTPUser = os.Getenv("AUTH_SMTP_USER")
	cfg.SMTPPass = os.Getenv("AUTH_SMTP_PASS")
	cfg.MailFrom = os.Getenv("AUTH_MAIL_FROM")
	cfg.VerifyURLBase = os.Getenv("AUTH_VERIFY_URL_BASE")
	cfg.ResetURLBase = os.Getenv("AUTH_RESET_URL_BASE")

	if cfg.IdleTTL <= 0 || cfg.AbsTTL <= 0 {
		return Config{}, fmt.Errorf("config: session TTLs must be positive (idle=%s, abs=%s)", cfg.IdleTTL, cfg.AbsTTL)
	}
	if cfg.IdleTTL > cfg.AbsTTL {
		return Config{}, fmt.Errorf("config: idle TTL %s exceeds absolute TTL %s", cfg.IdleTTL, cfg.AbsTTL)
	}
	if cfg.BcryptCost < minBcryptCost || cfg.BcryptCost > maxBcryptCost {
		return Config{}, fmt.Errorf("config: bcrypt cost %d out of range [%d,%d]", cfg.BcryptCost, minBcryptCost, maxBcryptCost)
	}

	// Mailer is all-or-nothing: if an SMTP server is set, the rest must be too,
	// so a half-configured mailer fails at startup rather than at first send.
	if cfg.SMTPEnabled() {
		for _, f := range []struct{ key, val string }{
			{"AUTH_SMTP_USER", cfg.SMTPUser},
			{"AUTH_SMTP_PASS", cfg.SMTPPass},
			{"AUTH_MAIL_FROM", cfg.MailFrom},
			{"AUTH_VERIFY_URL_BASE", cfg.VerifyURLBase},
			{"AUTH_RESET_URL_BASE", cfg.ResetURLBase},
		} {
			if f.val == "" {
				return Config{}, fmt.Errorf("config: %s is required when AUTH_SMTP_ADDR is set", f.key)
			}
		}
	}

	return cfg, nil
}

// rateLimitEnv reads <prefix>_LIMIT and <prefix>_WINDOW, falling back to def.
//
// A non-positive limit or window is rejected rather than clamped: unlike a
// missing variable, an explicitly configured "0" is someone stating an
// intention, and for a throttle the plausible intentions ("unlimited" or "block
// everything") are both things they should have to spell out some other way.
// Failing at startup beats silently running with no protection.
func rateLimitEnv(prefix string, def RateLimitPolicy) (RateLimitPolicy, error) {
	limit, err := intEnv(prefix+"_LIMIT", def.Limit)
	if err != nil {
		return RateLimitPolicy{}, err
	}
	window, err := durationEnv(prefix+"_WINDOW", def.Window)
	if err != nil {
		return RateLimitPolicy{}, err
	}
	if limit < 1 {
		return RateLimitPolicy{}, fmt.Errorf("config: %s_LIMIT must be >= 1, got %d", prefix, limit)
	}
	if window <= 0 {
		return RateLimitPolicy{}, fmt.Errorf("config: %s_WINDOW must be positive, got %s", prefix, window)
	}
	return RateLimitPolicy{Limit: limit, Window: window}, nil
}

func durationEnv(key string, def time.Duration) (time.Duration, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("config: %s: invalid duration %q: %w", key, v, err)
	}
	return d, nil
}

func intEnv(key string, def int) (int, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("config: %s: invalid integer %q: %w", key, v, err)
	}
	return n, nil
}

func boolEnv(key string, def bool) (bool, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("config: %s: invalid bool %q: %w", key, v, err)
	}
	return b, nil
}
