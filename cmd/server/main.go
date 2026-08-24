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
	screen := screener.NoOp{}
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
	opts := httpapi.Options{
		CookieSecure: cfg.CookieSecure,
		SessionTTL:   cfg.AbsTTL,
		CSRFKey:      csrfKey,
	}

	return &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           httpapi.NewRouter(deps, opts),
		ReadHeaderTimeout: 10 * time.Second,
	}, nil
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
