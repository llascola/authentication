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

// Config is the resolved server configuration.
type Config struct {
	ListenAddr   string
	IdleTTL      time.Duration
	AbsTTL       time.Duration
	BcryptCost   int
	CookieSecure bool
}

// Defaults applied when an env var is unset.
const (
	defaultListenAddr = ":8080"
	defaultIdleTTL    = 30 * time.Minute
	defaultAbsTTL     = 24 * time.Hour
	defaultBcryptCost = 10 // bcrypt.DefaultCost
)

// Load reads configuration from the environment, applying defaults for unset
// values and rejecting malformed or out-of-range ones.
func Load() (Config, error) {
	cfg := Config{
		ListenAddr:   defaultListenAddr,
		IdleTTL:      defaultIdleTTL,
		AbsTTL:       defaultAbsTTL,
		BcryptCost:   defaultBcryptCost,
		CookieSecure: true,
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

	if cfg.IdleTTL <= 0 || cfg.AbsTTL <= 0 {
		return Config{}, fmt.Errorf("config: session TTLs must be positive (idle=%s, abs=%s)", cfg.IdleTTL, cfg.AbsTTL)
	}
	if cfg.IdleTTL > cfg.AbsTTL {
		return Config{}, fmt.Errorf("config: idle TTL %s exceeds absolute TTL %s", cfg.IdleTTL, cfg.AbsTTL)
	}
	if cfg.BcryptCost < minBcryptCost || cfg.BcryptCost > maxBcryptCost {
		return Config{}, fmt.Errorf("config: bcrypt cost %d out of range [%d,%d]", cfg.BcryptCost, minBcryptCost, maxBcryptCost)
	}

	return cfg, nil
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
