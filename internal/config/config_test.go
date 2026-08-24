package config_test

import (
	"testing"
	"time"

	"authentication/internal/config"
)

func TestLoadDefaults(t *testing.T) {
	// No AUTH_* env set (t.Setenv not used) -> defaults. Guard against a polluted
	// environment by clearing the keys.
	for _, k := range []string{"AUTH_LISTEN_ADDR", "AUTH_SESSION_IDLE_TTL", "AUTH_SESSION_ABS_TTL", "AUTH_BCRYPT_COST", "AUTH_COOKIE_SECURE"} {
		t.Setenv(k, "")
	}
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ListenAddr != ":8080" {
		t.Errorf("ListenAddr = %q, want :8080", cfg.ListenAddr)
	}
	if cfg.IdleTTL != 30*time.Minute {
		t.Errorf("IdleTTL = %s, want 30m", cfg.IdleTTL)
	}
	if cfg.AbsTTL != 24*time.Hour {
		t.Errorf("AbsTTL = %s, want 24h", cfg.AbsTTL)
	}
	if cfg.BcryptCost != 10 {
		t.Errorf("BcryptCost = %d, want 10", cfg.BcryptCost)
	}
	if !cfg.CookieSecure {
		t.Error("CookieSecure = false, want true by default")
	}
}

func TestLoadOverrides(t *testing.T) {
	t.Setenv("AUTH_LISTEN_ADDR", "127.0.0.1:9000")
	t.Setenv("AUTH_SESSION_IDLE_TTL", "15m")
	t.Setenv("AUTH_SESSION_ABS_TTL", "12h")
	t.Setenv("AUTH_BCRYPT_COST", "12")
	t.Setenv("AUTH_COOKIE_SECURE", "false")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ListenAddr != "127.0.0.1:9000" || cfg.IdleTTL != 15*time.Minute ||
		cfg.AbsTTL != 12*time.Hour || cfg.BcryptCost != 12 || cfg.CookieSecure {
		t.Errorf("overrides not applied: %+v", cfg)
	}
}

func TestLoadInvalidDuration(t *testing.T) {
	t.Setenv("AUTH_SESSION_IDLE_TTL", "not-a-duration")
	if _, err := config.Load(); err == nil {
		t.Error("Load with bad duration returned nil error")
	}
}

func TestLoadInvalidBcryptCost(t *testing.T) {
	t.Setenv("AUTH_BCRYPT_COST", "99")
	if _, err := config.Load(); err == nil {
		t.Error("Load with out-of-range cost returned nil error")
	}
}

func TestLoadIdleExceedsAbs(t *testing.T) {
	t.Setenv("AUTH_SESSION_IDLE_TTL", "48h")
	t.Setenv("AUTH_SESSION_ABS_TTL", "24h")
	if _, err := config.Load(); err == nil {
		t.Error("Load with idle > abs returned nil error")
	}
}

func TestLoadMailerDisabledByDefault(t *testing.T) {
	t.Setenv("AUTH_SMTP_ADDR", "")
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.SMTPEnabled() {
		t.Error("SMTPEnabled() = true with no AUTH_SMTP_ADDR, want false")
	}
}

func TestLoadMailerFullyConfigured(t *testing.T) {
	t.Setenv("AUTH_SMTP_ADDR", "smtp.example.com:587")
	t.Setenv("AUTH_SMTP_USER", "user")
	t.Setenv("AUTH_SMTP_PASS", "pass")
	t.Setenv("AUTH_MAIL_FROM", "no-reply@example.com")
	t.Setenv("AUTH_VERIFY_URL_BASE", "https://app.example.com/verify")
	t.Setenv("AUTH_RESET_URL_BASE", "https://app.example.com/reset")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.SMTPEnabled() {
		t.Error("SMTPEnabled() = false, want true")
	}
	if cfg.MailFrom != "no-reply@example.com" || cfg.ResetURLBase != "https://app.example.com/reset" {
		t.Errorf("mailer fields not loaded: %+v", cfg)
	}
}

func TestLoadMailerPartialRejected(t *testing.T) {
	// SMTPAddr set but a required companion (from) missing -> error.
	t.Setenv("AUTH_SMTP_ADDR", "smtp.example.com:587")
	t.Setenv("AUTH_SMTP_USER", "user")
	t.Setenv("AUTH_SMTP_PASS", "pass")
	t.Setenv("AUTH_VERIFY_URL_BASE", "https://app.example.com/verify")
	t.Setenv("AUTH_RESET_URL_BASE", "https://app.example.com/reset")
	// AUTH_MAIL_FROM deliberately unset.
	if _, err := config.Load(); err == nil {
		t.Error("Load with partial mailer config returned nil error")
	}
}

func TestLoadRateLimitDefaults(t *testing.T) {
	for _, k := range []string{
		"AUTH_RATELIMIT_LOGIN_LIMIT", "AUTH_RATELIMIT_LOGIN_WINDOW",
		"AUTH_RATELIMIT_REGISTER_LIMIT", "AUTH_RATELIMIT_REGISTER_WINDOW",
		"AUTH_RATELIMIT_FORGOT_LIMIT", "AUTH_RATELIMIT_FORGOT_WINDOW",
		"AUTH_RATELIMIT_RESEND_LIMIT", "AUTH_RATELIMIT_RESEND_WINDOW",
	} {
		t.Setenv(k, "")
	}
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Every policy must default to something usable: an unset variable can never
	// leave a route with a zero budget (locks everyone out) or a zero window.
	for name, p := range map[string]config.RateLimitPolicy{
		"login":    cfg.LoginRate,
		"register": cfg.RegisterRate,
		"forgot":   cfg.ForgotRate,
		"resend":   cfg.ResendRate,
	} {
		if p.Limit < 1 {
			t.Errorf("%s default limit = %d, want >= 1", name, p.Limit)
		}
		if p.Window <= 0 {
			t.Errorf("%s default window = %s, want > 0", name, p.Window)
		}
	}
	if cfg.LoginRate != (config.RateLimitPolicy{Limit: 10, Window: time.Minute}) {
		t.Errorf("LoginRate = %+v, want 10 per minute", cfg.LoginRate)
	}
	if cfg.ForgotRate != (config.RateLimitPolicy{Limit: 5, Window: time.Hour}) {
		t.Errorf("ForgotRate = %+v, want 5 per hour", cfg.ForgotRate)
	}
}

func TestLoadRateLimitFromEnv(t *testing.T) {
	t.Setenv("AUTH_RATELIMIT_LOGIN_LIMIT", "3")
	t.Setenv("AUTH_RATELIMIT_LOGIN_WINDOW", "30s")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.LoginRate != (config.RateLimitPolicy{Limit: 3, Window: 30 * time.Second}) {
		t.Errorf("LoginRate = %+v, want 3 per 30s", cfg.LoginRate)
	}
	// An override on one policy must not disturb the others.
	if cfg.ResendRate != (config.RateLimitPolicy{Limit: 5, Window: time.Hour}) {
		t.Errorf("ResendRate = %+v, want the untouched default", cfg.ResendRate)
	}
}

// TestLoadRateLimitRejectsDisabling pins the security decision: an explicitly
// configured zero is refused at startup rather than clamped, so nobody switches
// a throttle off by accident and finds out from an SMTP bill.
func TestLoadRateLimitRejectsDisabling(t *testing.T) {
	cases := map[string][2]string{
		"zero limit":     {"AUTH_RATELIMIT_LOGIN_LIMIT", "0"},
		"negative limit": {"AUTH_RATELIMIT_LOGIN_LIMIT", "-1"},
		"zero window":    {"AUTH_RATELIMIT_LOGIN_WINDOW", "0s"},
		"bad integer":    {"AUTH_RATELIMIT_LOGIN_LIMIT", "lots"},
		"bad duration":   {"AUTH_RATELIMIT_LOGIN_WINDOW", "soon"},
	}
	for name, kv := range cases {
		t.Run(name, func(t *testing.T) {
			t.Setenv(kv[0], kv[1])
			if _, err := config.Load(); err == nil {
				t.Errorf("Load with %s=%q returned nil error", kv[0], kv[1])
			}
		})
	}
}

func TestLoadCSRFKey(t *testing.T) {
	t.Run("unset leaves it empty for the composition root", func(t *testing.T) {
		t.Setenv("AUTH_CSRF_KEY", "")
		cfg, err := config.Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if len(cfg.CSRFKey) != 0 {
			t.Errorf("CSRFKey = %q, want empty when unset", cfg.CSRFKey)
		}
	})

	t.Run("a long enough key is taken verbatim", func(t *testing.T) {
		const key = "0123456789abcdef0123456789abcdef" // exactly 32
		t.Setenv("AUTH_CSRF_KEY", key)
		cfg, err := config.Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if string(cfg.CSRFKey) != key {
			t.Errorf("CSRFKey = %q, want %q", cfg.CSRFKey, key)
		}
	})

	// A short key is rejected rather than stretched: the whole scheme rests on
	// this value being unguessable, and silently accepting a passphrase would
	// hide that.
	t.Run("a short key is rejected", func(t *testing.T) {
		t.Setenv("AUTH_CSRF_KEY", "too-short")
		if _, err := config.Load(); err == nil {
			t.Error("Load with a short AUTH_CSRF_KEY returned nil error")
		}
	})
}
