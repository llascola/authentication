package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"authentication/internal/adapter/screener"
	"authentication/internal/config"
)

// testConfig mirrors what config.Load produces with no environment set, minus
// the bcrypt cost (4, so tests are not spending real work factors).
func testConfig() config.Config {
	return config.Config{
		ListenAddr:       "127.0.0.1:0",
		IdleTTL:          30 * time.Minute,
		AbsTTL:           24 * time.Hour,
		BcryptCost:       4,
		CookieSecure:     true,
		Screener:         config.ScreenerNoOp,
		ScreenerTimeout:  3 * time.Second,
		ScreenerFailOpen: true,
		LoginRate:        config.RateLimitPolicy{Limit: 10, Window: time.Minute},
		RegisterRate:     config.RateLimitPolicy{Limit: 10, Window: time.Hour},
		ForgotRate:       config.RateLimitPolicy{Limit: 5, Window: time.Hour},
		ResendRate:       config.RateLimitPolicy{Limit: 5, Window: time.Hour},
	}
}

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestNewServerBuildsDependencyGraph(t *testing.T) {
	srv, err := newServer(testConfig(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	if srv == nil {
		t.Fatal("newServer returned nil")
	}
	if srv.Handler == nil {
		t.Error("server has no handler; wiring incomplete")
	}
	if srv.Addr != "127.0.0.1:0" {
		t.Errorf("Addr = %q, want 127.0.0.1:0", srv.Addr)
	}
}

func TestNewServerWithSMTPMailer(t *testing.T) {
	cfg := testConfig()
	cfg.SMTPAddr = "smtp.example.com:587"
	cfg.SMTPUser, cfg.SMTPPass, cfg.MailFrom = "u", "p", "no-reply@example.com"
	cfg.VerifyURLBase = "https://app.example.com/verify"
	cfg.ResetURLBase = "https://app.example.com/reset"

	if _, err := newServer(cfg, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatalf("newServer with valid SMTP config: %v", err)
	}
}

func TestNewServerRejectsBadSMTPBase(t *testing.T) {
	cfg := testConfig()
	cfg.SMTPAddr = "smtp.example.com:587"
	cfg.SMTPUser, cfg.SMTPPass, cfg.MailFrom = "u", "p", "no-reply@example.com"
	cfg.VerifyURLBase = "http://app.example.com/verify" // not https
	cfg.ResetURLBase = "https://app.example.com/reset"

	if _, err := newServer(cfg, slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
		t.Error("newServer with non-https verify base returned nil error")
	}
}

// TestBuildScreenerSelection pins the composition root's screener choice. Which
// implementation is wired decides whether breach screening happens at all, and
// ADR 0011 dropped composition rules on the assumption that it does — so a
// silent wrong turn here weakens the password policy with nothing to show for it.
func TestBuildScreenerSelection(t *testing.T) {
	t.Run("noop by default", func(t *testing.T) {
		cfg := testConfig()
		if _, ok := buildScreener(cfg, discardLog()).(screener.NoOp); !ok {
			t.Errorf("screener = %T, want screener.NoOp", buildScreener(cfg, discardLog()))
		}
	})

	t.Run("hibp wrapped in fail-open", func(t *testing.T) {
		cfg := testConfig()
		cfg.Screener, cfg.ScreenerFailOpen = config.ScreenerHIBP, true

		got := buildScreener(cfg, discardLog())
		fo, ok := got.(screener.FailOpen)
		if !ok {
			t.Fatalf("screener = %T, want screener.FailOpen", got)
		}
		if _, ok := fo.Inner.(*screener.HIBP); !ok {
			t.Errorf("FailOpen wraps %T, want *screener.HIBP", fo.Inner)
		}
	})

	t.Run("hibp bare when fail-open is off", func(t *testing.T) {
		cfg := testConfig()
		cfg.Screener, cfg.ScreenerFailOpen = config.ScreenerHIBP, false

		if _, ok := buildScreener(cfg, discardLog()).(*screener.HIBP); !ok {
			t.Error("fail-open disabled still produced a wrapped screener")
		}
	})
}

func TestCSRFKeyUsesTheConfiguredSecret(t *testing.T) {
	cfg := testConfig()
	cfg.CSRFKey = []byte("a-configured-key-of-at-least-32-bytes")

	got, err := csrfKey(cfg, discardLog())
	if err != nil {
		t.Fatalf("csrfKey: %v", err)
	}
	if string(got) != string(cfg.CSRFKey) {
		t.Errorf("csrfKey = %q, want the configured secret", got)
	}
}

// TestCSRFKeyFallsBackToAnEphemeralSecret: an unset AUTH_CSRF_KEY must still
// yield a real key rather than an empty one — NewRouter panics on empty, and a
// short or fixed fallback would make every token forgeable from this source.
func TestCSRFKeyFallsBackToAnEphemeralSecret(t *testing.T) {
	first, err := csrfKey(testConfig(), discardLog())
	if err != nil {
		t.Fatalf("csrfKey: %v", err)
	}
	if len(first) != 32 {
		t.Errorf("ephemeral key is %d bytes, want 32", len(first))
	}
	second, err := csrfKey(testConfig(), discardLog())
	if err != nil {
		t.Fatalf("csrfKey: %v", err)
	}
	if string(first) == string(second) {
		t.Error("two ephemeral keys were identical; they are not being generated")
	}
}

// TestNewServerEnforcesTheConfiguredRateLimit closes the loop the unit tests
// leave open: middleware_test proves the limiter throttles, config_test proves
// the numbers are read, and this proves the composition root actually joins the
// two. A limiter built from the wrong policy would pass both of those and still
// ship a route with the wrong budget.
func TestNewServerEnforcesTheConfiguredRateLimit(t *testing.T) {
	cfg := testConfig()
	cfg.LoginRate = config.RateLimitPolicy{Limit: 1, Window: time.Hour}

	srv, err := newServer(cfg, discardLog())
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}

	login := func() int {
		body := strings.NewReader(`{"email":"nobody@example.com","password":"whatever"}`)
		r := httptest.NewRequest(http.MethodPost, "/auth/login", body)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		srv.Handler.ServeHTTP(w, r)
		return w.Code
	}

	// The account does not exist, so the first attempt is a normal 401 — the
	// throttle is not an existence oracle.
	if got := login(); got != http.StatusUnauthorized {
		t.Fatalf("first login = %d, want 401", got)
	}
	if got := login(); got != http.StatusTooManyRequests {
		t.Errorf("second login = %d, want 429 (limit of 1/hour was not wired)", got)
	}
}

func TestServerStartsAndShutsDownCleanly(t *testing.T) {
	srv, err := newServer(testConfig(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()

	// The server is up; a graceful shutdown must return without error.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if err := <-serveErr; err != nil && err != http.ErrServerClosed {
		t.Fatalf("Serve returned %v, want ErrServerClosed", err)
	}
}
