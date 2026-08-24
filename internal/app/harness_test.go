package app_test

import (
	"bytes"
	"context"
	"log/slog"
	"regexp"
	"testing"
	"time"

	"authentication/internal/adapter/crypto"
	"authentication/internal/adapter/mailer"
	"authentication/internal/adapter/memory"
	"authentication/internal/adapter/screener"
	"authentication/internal/adapter/text"
	"authentication/internal/app"
	"authentication/internal/domain"
)

var (
	ctx       = context.Background()
	timeFixed = time.Date(2026, 6, 27, 12, 0, 0, 0, time.UTC)

	// goodPassword satisfies DefaultPasswordPolicy (>= 12 chars, no composition
	// rules). reusable across tests.
	goodPassword = "correct horse battery staple"
	newPassword  = "an even longer replacement passphrase 9000"
)

// testClock is a settable port.Clock for pinning time.
type testClock struct{ now time.Time }

func (c *testClock) Now() time.Time { return c.now }
func (c *testClock) advance(d time.Duration) {
	c.now = c.now.Add(d)
}

// harness wires every use-case over real adapters and the in-memory store, so
// tests exercise the actual crypto, normalization, and persistence paths.
type harness struct {
	clock   *testClock
	store   *memory.Store
	mailLog *bytes.Buffer

	register *app.RegisterService
	verify   *app.VerifyEmailService
	resend   *app.ResendVerificationService
	login    *app.LoginService
	validate *app.ValidateSessionService
	logout   *app.LogoutService
	change   *app.ChangePasswordService
	forgot   *app.ForgotPasswordService
	reset    *app.ResetPasswordService
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	clock := &testClock{now: timeFixed}
	store := memory.NewStore()
	bc := crypto.NewBcrypt(4) // bcrypt.MinCost: fast, still real
	tg := crypto.TokenGen{}
	nz := text.NFC{}
	sc := screener.NoOp{}
	policy := domain.DefaultPasswordPolicy()

	var buf bytes.Buffer
	ml := mailer.NewLogMailer(slog.New(slog.NewTextHandler(&buf, nil)))

	const idleTTL, absTTL = time.Hour, 24 * time.Hour

	return &harness{
		clock:   clock,
		store:   store,
		mailLog: &buf,
		register: app.NewRegisterService(
			store.Users(), store.Credentials(), store.Tokens(), ml, tg, clock, nz, policy, sc, bc),
		verify: app.NewVerifyEmailService(store.Users(), store.Tokens(), tg, clock),
		resend: app.NewResendVerificationService(store.Users(), store.Tokens(), ml, tg, clock),
		login: app.NewLoginService(
			store.Users(), store.Credentials(), store.Sessions(), bc, tg, bc, nz, clock, idleTTL, absTTL),
		validate: app.NewValidateSessionService(store.Sessions(), tg, clock),
		logout:   app.NewLogoutService(store.Sessions(), tg, clock),
		change: app.NewChangePasswordService(
			store.Credentials(), store.Sessions(), bc, nz, policy, sc, bc, clock),
		forgot: app.NewForgotPasswordService(store.Users(), store.Tokens(), ml, tg, clock),
		reset: app.NewResetPasswordService(
			store.Credentials(), store.Sessions(), store.Tokens(), tg, nz, policy, sc, bc, clock),
	}
}

var tokenRe = regexp.MustCompile(`token=([^\s]+)`)

// lastMailedToken returns the most recent raw token the stub mailer logged, and
// clears the buffer so the next call sees only fresh output.
func (h *harness) lastMailedToken(t *testing.T) string {
	t.Helper()
	matches := tokenRe.FindAllStringSubmatch(h.mailLog.String(), -1)
	if len(matches) == 0 {
		t.Fatal("no token found in mailer output")
	}
	h.mailLog.Reset()
	return matches[len(matches)-1][1]
}

// testDevice is a fixed DeviceInfo for login tests.
func testDevice(t *testing.T) domain.DeviceInfo {
	t.Helper()
	d, err := domain.NewDeviceInfo("203.0.113.7", "test-agent", "laptop")
	if err != nil {
		t.Fatalf("NewDeviceInfo: %v", err)
	}
	return d
}

// registerPending creates an account and leaves it unverified (StatusPending),
// discarding the registration token and clearing the mail log so a following
// assertion sees only fresh output.
func (h *harness) registerPending(t *testing.T, email string) string {
	t.Helper()
	if err := h.register.Register(ctx, email, goodPassword); err != nil {
		t.Fatalf("Register: %v", err)
	}
	_ = h.lastMailedToken(t)
	return email
}

// deactivate closes the account behind rawEmail, moving it out of StatusPending.
func (h *harness) deactivate(t *testing.T, rawEmail string) {
	t.Helper()
	email, err := domain.NewEmail(rawEmail)
	if err != nil {
		t.Fatalf("NewEmail: %v", err)
	}
	u, err := h.store.Users().FindByEmail(ctx, email)
	if err != nil {
		t.Fatalf("FindByEmail: %v", err)
	}
	if err := u.Deactivate(h.clock.now); err != nil {
		t.Fatalf("Deactivate: %v", err)
	}
	if err := h.store.Users().Update(ctx, u); err != nil {
		t.Fatalf("Update: %v", err)
	}
}

// registerAndVerify creates an active, verified account and returns its email.
func (h *harness) registerAndVerify(t *testing.T, email string) string {
	t.Helper()
	if err := h.register.Register(ctx, email, goodPassword); err != nil {
		t.Fatalf("Register: %v", err)
	}
	tok := h.lastMailedToken(t)
	if err := h.verify.VerifyEmail(ctx, tok); err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}
	return email
}
