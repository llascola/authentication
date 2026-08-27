// Command server is the composition root: the one place concrete adapters meet
// the application use-cases. Swapping the in-memory store for Postgres, or the
// no-op breach screener for a real one, changes only this file plus the new
// adapter — the use-cases and domain are untouched.
package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"authentication/internal/adapter/clock"
	"authentication/internal/adapter/crypto"
	httpapi "authentication/internal/adapter/http"
	"authentication/internal/adapter/mailer"
	"authentication/internal/adapter/memory"
	"authentication/internal/adapter/ratelimit"
	"authentication/internal/adapter/screener"
	"authentication/internal/adapter/text"
	"authentication/internal/app"
	"authentication/internal/config"
	"authentication/internal/domain"
	"authentication/internal/port"
)

const shutdownTimeout = 10 * time.Second

// Server timeouts.
//
// ReadHeaderTimeout on its own leaves the request BODY unbounded in time.
// MaxBytesReader caps how many bytes a request may carry (64 KiB), not how
// slowly they may arrive, so a client dribbling a body one byte per minute
// holds a connection and a goroutine indefinitely — the classic slow-loris,
// aimed at the body instead of the headers.
//
// It lands somewhere particularly bad here: the per-email rate limiter reads
// the body itself, before the handler, so the stall happens INSIDE the
// middleware and the throttle never gets to count a request that never
// finishes. No limit can bound a request that does not complete; only a
// deadline can.
//
// The values are generous by orders of magnitude for auth payloads, which are a
// few hundred bytes and finish in well under a second.
const (
	readHeaderTimeout = 10 * time.Second
	readTimeout       = 15 * time.Second
	idleTimeout       = 60 * time.Second

	// baseWriteTimeout is the floor for producing a response.
	baseWriteTimeout = 15 * time.Second

	// screenerWriteMargin is what the write budget reserves for everything the
	// register and reset paths do BESIDES the breach-screen call: the bcrypt
	// hash at the configured cost, the repository writes, and the mail handoff.
	screenerWriteMargin = 10 * time.Second
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(log)

	if err := run(log); err != nil {
		log.Error("server exited with error", "err", err)
		os.Exit(1)
	}
}

// run loads config, builds the server, serves, and blocks until a termination
// signal triggers a graceful shutdown.
func run(log *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	srv, err := newServer(cfg, log)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	serveErr := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.ListenAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
		}
	}()

	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
		log.Info("shutdown signal received")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

// newServer builds every adapter, wires the use-cases, mounts the router, and
// returns a ready-but-unstarted *http.Server. It is the documented dependency
// graph of the process and the seam tests use to assert wiring. It returns an
// error only when a configured adapter (currently the SMTP mailer) fails to
// build.
func newServer(cfg config.Config, log *slog.Logger) (*http.Server, error) {
	// Adapters (infrastructure).
	store := memory.NewStore()
	hasher := crypto.NewBcrypt(cfg.BcryptCost) // PasswordHasher + Authenticator
	tokens := crypto.TokenGen{}
	mail, err := buildMailer(cfg, log)
	if err != nil {
		return nil, err
	}
	screen := buildScreener(cfg, log)
	normalizer := text.NFC{}
	clk := clock.System{}
	policy := domain.DefaultPasswordPolicy()

	// Use-cases (application), each given only the ports it needs.
	deps := httpapi.Deps{
		Limits: httpapi.Limits{
			Login:    ratelimit.NewMemory(cfg.LoginRate.Limit, cfg.LoginRate.Window, clk),
			Register: ratelimit.NewMemory(cfg.RegisterRate.Limit, cfg.RegisterRate.Window, clk),
			Forgot:   ratelimit.NewMemory(cfg.ForgotRate.Limit, cfg.ForgotRate.Window, clk),
			Resend:   ratelimit.NewMemory(cfg.ResendRate.Limit, cfg.ResendRate.Window, clk),
		},
		Register: app.NewRegisterService(
			store.Users(), store.Credentials(), store.Tokens(), mail, tokens, clk, normalizer, policy, screen, hasher),
		VerifyEmail:        app.NewVerifyEmailService(store.Users(), store.Tokens(), tokens, clk),
		ResendVerification: app.NewResendVerificationService(store.Users(), store.Tokens(), mail, tokens, clk),
		Login:              app.NewLoginService(store.Users(), store.Credentials(), store.Sessions(), hasher, tokens, hasher, normalizer, clk, cfg.IdleTTL, cfg.AbsTTL),
		ValidateSession:    app.NewValidateSessionService(store.Sessions(), tokens, clk),
		Logout:             app.NewLogoutService(store.Sessions(), tokens, clk),
		ChangePassword:     app.NewChangePasswordService(store.Credentials(), store.Sessions(), hasher, normalizer, policy, screen, hasher, clk),
		ForgotPassword:     app.NewForgotPasswordService(store.Users(), store.Tokens(), mail, tokens, clk),
		ResetPassword:      app.NewResetPasswordService(store.Credentials(), store.Sessions(), store.Tokens(), tokens, normalizer, policy, screen, hasher, clk),
	}
	csrfKey, err := csrfKey(cfg, log)
	if err != nil {
		return nil, err
	}
	logClientIPResolution(cfg, log)
	opts := httpapi.Options{
		CookieSecure:     cfg.CookieSecure,
		SessionTTL:       cfg.AbsTTL,
		CSRFKey:          csrfKey,
		TrustedProxyHops: cfg.TrustedProxyHops,
	}

	return &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           httpapi.NewRouter(deps, opts),
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout(cfg),
		IdleTimeout:       idleTimeout,
	}, nil
}

// writeTimeout derives the response-write budget from config instead of fixing
// it, because the duration of the slowest handler is itself configurable: the
// register and password-reset paths block on the breach screener for up to
// AUTH_SCREENER_TIMEOUT before they write anything.
//
// A hard-coded budget would silently start cutting those requests off the
// moment an operator raised the screener timeout past it — two independently
// sensible numbers interacting, which is the kind of thing only found in
// production. Tying them together means raising one cannot break the other.
func writeTimeout(cfg config.Config) time.Duration {
	return max(baseWriteTimeout, cfg.ScreenerTimeout+screenerWriteMargin)
}

// logClientIPResolution states at startup how the client address is being
// derived, because both plausible misconfigurations are silent.
//
// Running behind a proxy with hops at 0 makes every request appear to come from
// the proxy, which collapses the per-IP rate limits into a single bucket shared
// by every user — an outage that arrives without an attacker and shows up as
// "logins started returning 429" long after the deploy that caused it. Running
// with hops set while directly reachable is the opposite failure: the header
// becomes forgeable and the limit stops limiting.
//
// Neither is visible from inside the process, so the resolution in force is
// logged rather than inferred. It is Info, not Warn: 0 is correct for a directly
// exposed server and must not cry wolf.
func logClientIPResolution(cfg config.Config, log *slog.Logger) {
	if cfg.TrustedProxyHops == 0 {
		log.Info("client IP comes from RemoteAddr; no forwarding header is trusted",
			"trusted_proxy_hops", 0,
			"impact", "behind a reverse proxy every request keys to the proxy, collapsing per-IP rate limits into one shared bucket",
			"action", "if a proxy terminates TLS in front of this server, set AUTH_TRUSTED_PROXY_HOPS to the number of proxies you operate")
		return
	}
	log.Info("client IP comes from X-Forwarded-For",
		"trusted_proxy_hops", cfg.TrustedProxyHops,
		"entry", "counted from the right",
		"assumes", "this server is reachable only through those proxies; direct reachability makes the header forgeable")
}

// buildScreener selects the breach screener from config: the HIBP range API
// when asked for, otherwise the no-op that accepts everything.
//
// The no-op is the default so a fresh checkout and CI stay offline, but it
// provides no protection — and ADR 0011 dropped composition rules precisely
// because breach screening was supposed to replace them. Running with it in a
// real deployment leaves the password policy weaker than that ADR intends, so
// say so loudly at startup rather than in a comment nobody reads.
//
// Fail-open is applied here, as a visible wrapper at the wiring site, because it
// is a security decision rather than an error-handling detail (ADR 0019).
func buildScreener(cfg config.Config, log *slog.Logger) port.PasswordScreener {
	if cfg.Screener != config.ScreenerHIBP {
		log.Warn("breach screening is disabled; every password is accepted",
			"screener", cfg.Screener,
			"impact", "ADR 0011 removed composition rules on the assumption this screen exists",
			"action", "set AUTH_PASSWORD_SCREENER=hibp")
		return screener.NoOp{}
	}

	var s port.PasswordScreener = screener.NewHIBP(&http.Client{Timeout: cfg.ScreenerTimeout})
	if cfg.ScreenerFailOpen {
		s = screener.FailOpen{Inner: s, Log: log}
	}
	log.Info("breach screening enabled",
		"screener", config.ScreenerHIBP, "timeout", cfg.ScreenerTimeout, "fail_open", cfg.ScreenerFailOpen)
	return s
}

// csrfKey resolves the secret CSRF tokens are signed with.
//
// An unset AUTH_CSRF_KEY yields a random per-process key rather than an error,
// which is only defensible while sessions live in memory: a restart drops every
// session and every token together, so nothing is left holding a token this
// process can no longer verify. Phase 07 makes sessions outlive the process, at
// which point an ephemeral key would log everyone out on every deploy and
// break horizontal scaling outright — hence the warning naming that, rather
// than a silent default.
func csrfKey(cfg config.Config, log *slog.Logger) ([]byte, error) {
	if len(cfg.CSRFKey) > 0 {
		return cfg.CSRFKey, nil
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate ephemeral CSRF key: %w", err)
	}
	log.Warn("AUTH_CSRF_KEY is unset; generated an ephemeral key",
		"impact", "CSRF tokens do not survive a restart and are not shared across replicas",
		"action", "set AUTH_CSRF_KEY before persisting sessions or running more than one instance")
	return key, nil
}

// buildMailer selects the mailer implementation from config: the production
// SmtpMailer when SMTP is configured, otherwise the dev-only LogMailer that logs
// the raw token (ADR 0016).
func buildMailer(cfg config.Config, log *slog.Logger) (port.Mailer, error) {
	if !cfg.SMTPEnabled() {
		return mailer.NewLogMailer(log), nil
	}
	return mailer.NewSmtpMailer(
		cfg.SMTPAddr, cfg.SMTPUser, cfg.SMTPPass, cfg.MailFrom, cfg.VerifyURLBase, cfg.ResetURLBase,
	)
}
