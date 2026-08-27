package memory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"authentication/internal/adapter/memory"
	"authentication/internal/domain"
	"authentication/internal/port"
)

var (
	ctx       = context.Background()
	timeFixed = time.Date(2026, 6, 27, 12, 0, 0, 0, time.UTC)
)

func mustEmail(t *testing.T, raw string) domain.Email {
	t.Helper()
	e, err := domain.NewEmail(raw)
	if err != nil {
		t.Fatalf("NewEmail(%q): %v", raw, err)
	}
	return e
}

func mustUser(t *testing.T, email string) *domain.User {
	t.Helper()
	u, err := domain.NewUser(timeFixed, mustEmail(t, email))
	if err != nil {
		t.Fatalf("NewUser: %v", err)
	}
	return u
}

func mustTokenHash(t *testing.T, b ...byte) domain.TokenHash {
	t.Helper()
	h, err := domain.NewTokenHash(b)
	if err != nil {
		t.Fatalf("NewTokenHash: %v", err)
	}
	return h
}

func mustSession(t *testing.T, userID domain.UserID, hash domain.TokenHash) *domain.Session {
	t.Helper()
	dev, err := domain.NewDeviceInfo("203.0.113.7", "test-agent", "laptop")
	if err != nil {
		t.Fatalf("NewDeviceInfo: %v", err)
	}
	s, err := domain.NewSession(timeFixed, userID, hash, domain.AAL1,
		[]domain.AuthMethod{domain.AuthMethodPassword}, dev, time.Hour, 24*time.Hour)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	return s
}

func mustToken(t *testing.T, userID domain.UserID, purpose domain.Purpose, hash domain.TokenHash) *domain.VerificationToken {
	t.Helper()
	tok, err := domain.NewVerificationToken(timeFixed, userID, purpose, hash)
	if err != nil {
		t.Fatalf("NewVerificationToken: %v", err)
	}
	return tok
}

func TestUserCreateRejectsDuplicateEmail(t *testing.T) {
	repo := memory.NewStore().Users()
	if err := repo.Create(ctx, mustUser(t, "a@example.com")); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	err := repo.Create(ctx, mustUser(t, "a@example.com"))
	if !errors.Is(err, port.ErrEmailTaken) {
		t.Fatalf("duplicate Create = %v, want ErrEmailTaken", err)
	}
}

func TestUserFindByEmailHitAndMiss(t *testing.T) {
	repo := memory.NewStore().Users()
	u := mustUser(t, "found@example.com")
	if err := repo.Create(ctx, u); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := repo.FindByEmail(ctx, mustEmail(t, "found@example.com"))
	if err != nil {
		t.Fatalf("FindByEmail hit: %v", err)
	}
	if got.ID() != u.ID() {
		t.Errorf("found id %v, want %v", got.ID(), u.ID())
	}

	if _, err := repo.FindByEmail(ctx, mustEmail(t, "missing@example.com")); err == nil {
		t.Error("FindByEmail miss returned nil error")
	}
}

func TestUserFindByIDMiss(t *testing.T) {
	repo := memory.NewStore().Users()
	if _, err := repo.FindByID(ctx, domain.NewUserID()); err == nil {
		t.Error("FindByID miss returned nil error")
	}
}

func TestUserStoredCopyIsIsolated(t *testing.T) {
	store := memory.NewStore()
	repo := store.Users()
	u := mustUser(t, "iso@example.com")
	if err := repo.Create(ctx, u); err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Mutate the caller's aggregate after Create; the store must not see it.
	if err := u.VerifyEmail(timeFixed); err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}
	got, err := repo.FindByID(ctx, u.ID())
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got.EmailVerified() {
		t.Error("store reflected a mutation made to the caller's copy after Create")
	}
}

func TestUserUpdateMiss(t *testing.T) {
	repo := memory.NewStore().Users()
	if err := repo.Update(ctx, mustUser(t, "nope@example.com")); !errors.Is(err, port.ErrUserNotFound) {
		t.Errorf("Update on missing user = %v, want ErrUserNotFound", err)
	}
}

func TestSessionFindRevokeAll(t *testing.T) {
	store := memory.NewStore()
	sessions := store.Sessions()
	uid := domain.NewUserID()

	s1 := mustSession(t, uid, mustTokenHash(t, 1, 1, 1))
	s2 := mustSession(t, uid, mustTokenHash(t, 2, 2, 2))
	other := mustSession(t, domain.NewUserID(), mustTokenHash(t, 3, 3, 3))
	for _, s := range []*domain.Session{s1, s2, other} {
		if err := sessions.Create(ctx, s); err != nil {
			t.Fatalf("Create: %v", err)
		}
	}

	// Hit + miss on FindByTokenHash.
	if _, err := sessions.FindByTokenHash(ctx, s1.TokenHash()); err != nil {
		t.Errorf("FindByTokenHash hit: %v", err)
	}
	if _, err := sessions.FindByTokenHash(ctx, mustTokenHash(t, 9, 9, 9)); err == nil {
		t.Error("FindByTokenHash miss returned nil error")
	}

	if err := sessions.RevokeAllForUser(ctx, uid, timeFixed.Add(time.Minute), "password changed"); err != nil {
		t.Fatalf("RevokeAllForUser: %v", err)
	}

	for _, s := range []*domain.Session{s1, s2} {
		got, err := sessions.FindByTokenHash(ctx, s.TokenHash())
		if err != nil {
			t.Fatalf("re-find: %v", err)
		}
		if got.Status() != domain.SessionRevoked {
			t.Errorf("session %v status = %v, want revoked", s.ID(), got.Status())
		}
	}
	// Other user's session untouched.
	got, err := sessions.FindByTokenHash(ctx, other.TokenHash())
	if err != nil {
		t.Fatalf("find other: %v", err)
	}
	if got.Status() != domain.SessionActive {
		t.Errorf("other user's session was revoked")
	}
}

func TestVerificationTokenInvalidatesPriorUnconsumed(t *testing.T) {
	store := memory.NewStore()
	tokens := store.Tokens()
	uid := domain.NewUserID()

	first := mustToken(t, uid, domain.PurposeEmailVerify, mustTokenHash(t, 10, 10))
	if err := tokens.Create(ctx, first); err != nil {
		t.Fatalf("Create first: %v", err)
	}
	second := mustToken(t, uid, domain.PurposeEmailVerify, mustTokenHash(t, 20, 20))
	if err := tokens.Create(ctx, second); err != nil {
		t.Fatalf("Create second: %v", err)
	}

	// Prior unconsumed token for the same (user, purpose) is now consumed.
	gotFirst, err := tokens.FindByTokenHash(ctx, first.TokenHash())
	if err != nil {
		t.Fatalf("find first: %v", err)
	}
	if !gotFirst.IsConsumed() {
		t.Error("prior token was not invalidated by a newer one")
	}
	// Newest stays valid.
	gotSecond, err := tokens.FindByTokenHash(ctx, second.TokenHash())
	if err != nil {
		t.Fatalf("find second: %v", err)
	}
	if gotSecond.IsConsumed() {
		t.Error("newest token should remain valid")
	}
}

func TestVerificationTokenDifferentPurposeNotInvalidated(t *testing.T) {
	store := memory.NewStore()
	tokens := store.Tokens()
	uid := domain.NewUserID()

	verify := mustToken(t, uid, domain.PurposeEmailVerify, mustTokenHash(t, 30, 30))
	reset := mustToken(t, uid, domain.PurposePasswordReset, mustTokenHash(t, 40, 40))
	if err := tokens.Create(ctx, verify); err != nil {
		t.Fatalf("Create verify: %v", err)
	}
	if err := tokens.Create(ctx, reset); err != nil {
		t.Fatalf("Create reset: %v", err)
	}

	got, err := tokens.FindByTokenHash(ctx, verify.TokenHash())
	if err != nil {
		t.Fatalf("find verify: %v", err)
	}
	if got.IsConsumed() {
		t.Error("a reset token must not invalidate an email-verify token")
	}
}

func TestVerificationTokenUpdateAndFindMiss(t *testing.T) {
	tokens := memory.NewStore().Tokens()
	if _, err := tokens.FindByTokenHash(ctx, mustTokenHash(t, 99)); err == nil {
		t.Error("FindByTokenHash miss returned nil error")
	}
	if err := tokens.Update(ctx, mustToken(t, domain.NewUserID(), domain.PurposeEmailVerify, mustTokenHash(t, 99))); err == nil {
		t.Error("Update on missing token returned nil error")
	}
}

func TestCredentialRoundTripAndMiss(t *testing.T) {
	store := memory.NewStore()
	creds := store.Credentials()
	uid := domain.NewUserID()

	if _, err := creds.FindByUserID(ctx, uid); err == nil {
		t.Error("FindByUserID miss returned nil error")
	}

	ph, err := domain.NewPasswordHash([]byte("$2a$10$stored.hash.placeholder"))
	if err != nil {
		t.Fatalf("NewPasswordHash: %v", err)
	}
	c, err := domain.NewPasswordCredential(timeFixed, uid, ph)
	if err != nil {
		t.Fatalf("NewPasswordCredential: %v", err)
	}
	if err := creds.Create(ctx, c); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := creds.FindByUserID(ctx, uid)
	if err != nil {
		t.Fatalf("FindByUserID: %v", err)
	}
	if got.UserID() != uid {
		t.Errorf("user id = %v, want %v", got.UserID(), uid)
	}
}

func TestSessionRevokeAllExcept(t *testing.T) {
	store := memory.NewStore()
	sessions := store.Sessions()
	uid := domain.NewUserID()

	keep := mustSession(t, uid, mustTokenHash(t, 4, 4, 4))
	drop := mustSession(t, uid, mustTokenHash(t, 5, 5, 5))
	other := mustSession(t, domain.NewUserID(), mustTokenHash(t, 6, 6, 6))
	for _, s := range []*domain.Session{keep, drop, other} {
		if err := sessions.Create(ctx, s); err != nil {
			t.Fatalf("Create: %v", err)
		}
	}

	if err := sessions.RevokeAllExcept(ctx, uid, keep.TokenHash(), timeFixed.Add(time.Minute), "password changed"); err != nil {
		t.Fatalf("RevokeAllExcept: %v", err)
	}

	status := func(s *domain.Session) domain.SessionStatus {
		t.Helper()
		got, err := sessions.FindByTokenHash(ctx, s.TokenHash())
		if err != nil {
			t.Fatalf("re-find: %v", err)
		}
		return got.Status()
	}
	if got := status(keep); got != domain.SessionActive {
		t.Errorf("spared session status = %v, want active", got)
	}
	if got := status(drop); got != domain.SessionRevoked {
		t.Errorf("other session of the same user = %v, want revoked", got)
	}
	// The sweep is scoped by user id, so a different user keeps their session
	// whether or not it was named.
	if got := status(other); got != domain.SessionActive {
		t.Errorf("another user's session = %v, want untouched", got)
	}
}

// TestSessionRevokeAllExceptZeroHashSparesNothing pins the degenerate case both
// revoke methods share: an empty keep hash matches no stored session, so the
// sweep takes everything. RevokeAllForUser is implemented on exactly this.
func TestSessionRevokeAllExceptZeroHashSparesNothing(t *testing.T) {
	store := memory.NewStore()
	sessions := store.Sessions()
	uid := domain.NewUserID()

	s := mustSession(t, uid, mustTokenHash(t, 7, 7, 7))
	if err := sessions.Create(ctx, s); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := sessions.RevokeAllExcept(ctx, uid, domain.TokenHash{}, timeFixed.Add(time.Minute), "password reset"); err != nil {
		t.Fatalf("RevokeAllExcept: %v", err)
	}
	got, err := sessions.FindByTokenHash(ctx, s.TokenHash())
	if err != nil {
		t.Fatalf("re-find: %v", err)
	}
	if got.Status() != domain.SessionRevoked {
		t.Errorf("status = %v, want revoked: a zero keep hash must spare nothing", got.Status())
	}
}

// TestSessionRevokeAllExceptLeavesRevokedAlone: a session already revoked is not
// re-stamped with a new instant or reason.
func TestSessionRevokeAllExceptLeavesRevokedAlone(t *testing.T) {
	store := memory.NewStore()
	sessions := store.Sessions()
	uid := domain.NewUserID()

	s := mustSession(t, uid, mustTokenHash(t, 8, 8, 8))
	if err := sessions.Create(ctx, s); err != nil {
		t.Fatalf("Create: %v", err)
	}
	first := timeFixed.Add(time.Minute)
	if err := sessions.RevokeAllForUser(ctx, uid, first, "logged out"); err != nil {
		t.Fatalf("RevokeAllForUser: %v", err)
	}
	if err := sessions.RevokeAllExcept(ctx, uid, domain.TokenHash{}, first.Add(time.Hour), "password changed"); err != nil {
		t.Fatalf("RevokeAllExcept: %v", err)
	}

	got, err := sessions.FindByTokenHash(ctx, s.TokenHash())
	if err != nil {
		t.Fatalf("re-find: %v", err)
	}
	if got.Reason() != "logged out" {
		t.Errorf("reason = %q, want the original %q: an already-revoked session must not be re-stamped", got.Reason(), "logged out")
	}
	revokedAt, ok := got.RevokedAt()
	if !ok || !revokedAt.Equal(first) {
		t.Errorf("revokedAt = %v (ok=%v), want the original %v", revokedAt, ok, first)
	}
}
