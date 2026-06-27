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
