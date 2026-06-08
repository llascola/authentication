package domain_test

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"authentication/internal/domain"
)

const (
	testIdleTTL = 30 * time.Minute
	testAbsTTL  = 2 * time.Hour
)

// --- helpers ---------------------------------------------------------------

func mustTokenHash(t *testing.T, b []byte) domain.TokenHash {
	t.Helper()
	h, err := domain.NewTokenHash(b)
	if err != nil {
		t.Fatalf("NewTokenHash: unexpected error: %v", err)
	}
	return h
}

func mustSession(t *testing.T) *domain.Session {
	t.Helper()
	s, err := domain.NewSession(
		timeFixed(),
		mustUserID(t),
		mustTokenHash(t, []byte("token-hash")),
		domain.AAL1,
		[]domain.AuthMethod{domain.AuthMethodPassword},
		domain.DeviceInfo{},
		testIdleTTL, testAbsTTL,
	)
	if err != nil {
		t.Fatalf("NewSession: unexpected error: %v", err)
	}
	return s
}

// --- SessionID -------------------------------------------------------------

func TestSessionID(t *testing.T) {
	id := domain.NewSessionID()
	if id.IsZero() {
		t.Fatal("NewSessionID returned zero id")
	}
	parsed, err := domain.ParseSessionID(id.String())
	if err != nil {
		t.Fatalf("ParseSessionID round-trip: %v", err)
	}
	if parsed != id {
		t.Errorf("round-trip = %v, want %v", parsed, id)
	}
	if _, err := domain.ParseSessionID("nope"); !errors.Is(err, domain.ErrInvalidSessionID) {
		t.Errorf("err = %v, want ErrInvalidSessionID", err)
	}
}

// --- TokenHash -------------------------------------------------------------

func TestNewTokenHash(t *testing.T) {
	if _, err := domain.NewTokenHash(nil); !errors.Is(err, domain.ErrEmptyTokenHash) {
		t.Errorf("nil err = %v, want ErrEmptyTokenHash", err)
	}
	h := mustTokenHash(t, []byte("abc"))
	if h.IsZero() || !bytes.Equal(h.Bytes(), []byte("abc")) {
		t.Error("token hash not stored correctly")
	}
}

func TestTokenHashBytesIsolation(t *testing.T) {
	in := []byte("tok")
	h := mustTokenHash(t, in)

	in[0] = 'X'
	if !bytes.Equal(h.Bytes(), []byte("tok")) {
		t.Error("constructor did not copy input")
	}
	out := h.Bytes()
	out[0] = 'Y'
	if !bytes.Equal(h.Bytes(), []byte("tok")) {
		t.Error("Bytes() exposed internal slice")
	}
}

func TestTokenHashEqual(t *testing.T) {
	h := mustTokenHash(t, []byte("token-hash"))

	tests := []struct {
		name  string
		other domain.TokenHash
		want  bool
	}{
		{"same bytes", mustTokenHash(t, []byte("token-hash")), true},
		{"different bytes same length", mustTokenHash(t, []byte("token-XXXX")), false},
		{"different length", mustTokenHash(t, []byte("token")), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := h.Equal(tc.other); got != tc.want {
				t.Errorf("Equal = %v, want %v", got, tc.want)
			}
			// symmetric
			if got := tc.other.Equal(h); got != tc.want {
				t.Errorf("Equal (reversed) = %v, want %v", got, tc.want)
			}
		})
	}
}

// --- AuthLevel -------------------------------------------------------------

func TestAuthLevel(t *testing.T) {
	if !domain.AAL1.Valid() || !domain.AAL2.Valid() {
		t.Error("AAL1/AAL2 should be valid")
	}
	if domain.AuthLevel(0).Valid() || domain.AuthLevel(99).Valid() {
		t.Error("invalid levels reported valid")
	}
	if domain.AAL1.String() != "aal1" || domain.AAL2.String() != "aal2" {
		t.Error("unexpected AuthLevel string")
	}
	if domain.AuthLevel(0).String() != "unknown" {
		t.Error("zero AuthLevel should stringify unknown")
	}
}

// --- SessionStatus ---------------------------------------------------------

func TestSessionStatusString(t *testing.T) {
	tests := map[domain.SessionStatus]string{
		domain.SessionActive:    "active",
		domain.SessionRevoked:   "revoked",
		domain.SessionExpired:   "expired",
		domain.SessionStatus(9): "unknown",
	}
	for s, want := range tests {
		if got := s.String(); got != want {
			t.Errorf("SessionStatus(%d).String() = %q, want %q", s, got, want)
		}
	}
}

// --- DeviceInfo ------------------------------------------------------------

func TestNewDeviceInfo(t *testing.T) {
	t.Run("valid ip", func(t *testing.T) {
		d, err := domain.NewDeviceInfo("192.168.1.10", "  Mozilla  ", "  laptop ")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if d.IP().String() != "192.168.1.10" {
			t.Errorf("ip = %v, want 192.168.1.10", d.IP())
		}
		if d.UserAgent() != "Mozilla" || d.Label() != "laptop" {
			t.Errorf("fields not trimmed: %q %q", d.UserAgent(), d.Label())
		}
	})

	t.Run("empty ip is unknown", func(t *testing.T) {
		d, err := domain.NewDeviceInfo("", "UA", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if d.IP().IsValid() {
			t.Error("empty ip should yield invalid (unknown) addr")
		}
	})

	t.Run("bad ip rejected", func(t *testing.T) {
		_, err := domain.NewDeviceInfo("999.1.1.1", "", "")
		if !errors.Is(err, domain.ErrInvalidIP) {
			t.Errorf("err = %v, want ErrInvalidIP", err)
		}
	})
}

// --- NewSession ------------------------------------------------------------

func TestNewSession(t *testing.T) {
	t.Run("ok and deadline invariants", func(t *testing.T) {
		s := mustSession(t)
		if s.ID().IsZero() {
			t.Error("id not set")
		}
		if s.Status() != domain.SessionActive {
			t.Errorf("status = %v, want active", s.Status())
		}
		if s.AuthLevel() != domain.AAL1 {
			t.Errorf("authLevel = %v, want aal1", s.AuthLevel())
		}
		// issuedAt is exactly the instant we passed; deadlines derive from it.
		if !s.IssuedAt().Equal(timeFixed()) {
			t.Errorf("issuedAt = %v, want %v", s.IssuedAt(), timeFixed())
		}
		if !s.AbsoluteExpiry().Equal(timeFixed().Add(testAbsTTL)) {
			t.Error("absExpiry != issuedAt + absoluteTTL")
		}
		if !s.IdleExpiry().Equal(timeFixed().Add(testIdleTTL)) {
			t.Error("idleExpiry != issuedAt + idleTTL")
		}
		if !s.LastSeenAt().Equal(s.IssuedAt()) {
			t.Error("lastSeenAt != issuedAt on creation")
		}
		if _, ok := s.RevokedAt(); ok {
			t.Error("new session should not be revoked")
		}
		if !s.UsedMethod(domain.AuthMethodPassword) {
			t.Errorf("amr not seeded: %v", s.AMR())
		}
	})

	uid := domain.NewUserID()
	hash := func(t *testing.T) domain.TokenHash { return mustTokenHash(t, []byte("h")) }

	tests := []struct {
		name      string
		userID    domain.UserID
		tokenHash domain.TokenHash
		level     domain.AuthLevel
		idle, abs time.Duration
		wantErr   error
	}{
		{"zero userID", domain.UserID{}, hash(t), domain.AAL1, testIdleTTL, testAbsTTL, domain.ErrInvalidUserID},
		{"empty token hash", uid, domain.TokenHash{}, domain.AAL1, testIdleTTL, testAbsTTL, domain.ErrEmptyTokenHash},
		{"bad auth level", uid, hash(t), domain.AuthLevel(0), testIdleTTL, testAbsTTL, domain.ErrInvalidAuthLevel},
		{"zero idle ttl", uid, hash(t), domain.AAL1, 0, testAbsTTL, domain.ErrInvalidTTL},
		{"zero abs ttl", uid, hash(t), domain.AAL1, testIdleTTL, 0, domain.ErrInvalidTTL},
		{"idle exceeds abs", uid, hash(t), domain.AAL1, testAbsTTL, testIdleTTL, domain.ErrInvalidTTL},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := domain.NewSession(timeFixed(), tc.userID, tc.tokenHash, tc.level, []domain.AuthMethod{domain.AuthMethodPassword}, domain.DeviceInfo{}, tc.idle, tc.abs)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestNewSessionIdleCappedAtAbsolute(t *testing.T) {
	// idleTTL == absoluteTTL: idle deadline must be clamped to the absolute cap.
	s, err := domain.NewSession(
		timeFixed(), mustUserID(t), mustTokenHash(t, []byte("h")),
		domain.AAL1, []domain.AuthMethod{domain.AuthMethodPassword}, domain.DeviceInfo{},
		testAbsTTL, testAbsTTL,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !s.IdleExpiry().Equal(s.AbsoluteExpiry()) {
		t.Error("idleExpiry not capped at absExpiry when idleTTL == absoluteTTL")
	}
}

// --- AuthMethod / amr ------------------------------------------------------

func TestAuthMethodValid(t *testing.T) {
	for _, m := range []domain.AuthMethod{
		domain.AuthMethodPassword, domain.AuthMethodOTP, domain.AuthMethodOAuth, domain.AuthMethodWebAuthn,
	} {
		if !m.Valid() {
			t.Errorf("%q should be valid", m)
		}
	}
	if domain.AuthMethod("face").Valid() {
		t.Error("unknown method reported valid")
	}
}

func TestNewSessionAMR(t *testing.T) {
	mk := func(methods []domain.AuthMethod) (*domain.Session, error) {
		return domain.NewSession(
			timeFixed(), mustUserID(t), mustTokenHash(t, []byte("h")),
			domain.AAL2, methods, domain.DeviceInfo{},
			testIdleTTL, testAbsTTL,
		)
	}

	t.Run("seeds and dedupes preserving order", func(t *testing.T) {
		s, err := mk([]domain.AuthMethod{domain.AuthMethodPassword, domain.AuthMethodOTP, domain.AuthMethodPassword})
		if err != nil {
			t.Fatal(err)
		}
		got := s.AMR()
		want := []domain.AuthMethod{domain.AuthMethodPassword, domain.AuthMethodOTP}
		if len(got) != len(want) {
			t.Fatalf("amr = %v, want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("amr[%d] = %v, want %v", i, got[i], want[i])
			}
		}
	})

	t.Run("empty methods rejected", func(t *testing.T) {
		if _, err := mk(nil); !errors.Is(err, domain.ErrNoAuthMethod) {
			t.Errorf("err = %v, want ErrNoAuthMethod", err)
		}
	})

	t.Run("invalid method rejected", func(t *testing.T) {
		if _, err := mk([]domain.AuthMethod{domain.AuthMethod("face")}); !errors.Is(err, domain.ErrInvalidAuthMethod) {
			t.Errorf("err = %v, want ErrInvalidAuthMethod", err)
		}
	})
}

func TestSessionAMRGetterIsCopy(t *testing.T) {
	s := mustSession(t)
	got := s.AMR()
	if len(got) == 0 {
		t.Fatal("expected seeded amr")
	}
	got[0] = domain.AuthMethodWebAuthn // mutate returned slice
	if s.UsedMethod(domain.AuthMethodWebAuthn) {
		t.Error("mutating returned slice leaked into aggregate")
	}
}

// --- IsExpired / IsActive --------------------------------------------------

func TestSessionExpiryQueries(t *testing.T) {
	s := mustSession(t)
	at := s.IssuedAt()

	tests := []struct {
		name        string
		now         time.Time
		wantExpired bool
	}{
		{"within both", at.Add(time.Minute), false},
		{"idle boundary exact", at.Add(testIdleTTL), false},
		{"past idle", at.Add(testIdleTTL + time.Second), true},
		{"past absolute", at.Add(testAbsTTL + time.Second), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := s.IsExpired(tc.now); got != tc.wantExpired {
				t.Errorf("IsExpired = %v, want %v", got, tc.wantExpired)
			}
			// active iff stored-active and not expired
			if got := s.IsActive(tc.now); got != !tc.wantExpired {
				t.Errorf("IsActive = %v, want %v", got, !tc.wantExpired)
			}
		})
	}
}

// --- Touch -----------------------------------------------------------------

func TestSessionTouch(t *testing.T) {
	s := mustSession(t)

	touchAt := timeFixed().Add(10 * time.Minute) // within the idle window
	if err := s.Touch(touchAt); err != nil {
		t.Fatalf("Touch: %v", err)
	}
	// Touch stamps exactly the instant given and slides idle from it.
	if !s.LastSeenAt().Equal(touchAt) {
		t.Errorf("lastSeenAt = %v, want %v", s.LastSeenAt(), touchAt)
	}
	if !s.IdleExpiry().Equal(touchAt.Add(testIdleTTL)) {
		t.Errorf("idleExpiry = %v, want %v", s.IdleExpiry(), touchAt.Add(testIdleTTL))
	}
}

func TestSessionTouchClampsIdleToAbsolute(t *testing.T) {
	// Session whose idle window is as long as the absolute cap, so a late Touch
	// would push idleExpiry past absExpiry — it must clamp to the cap.
	issued := timeFixed()
	s := domain.ReconstituteSession(
		domain.NewSessionID(), domain.NewUserID(), mustTokenHash(t, []byte("h")),
		domain.SessionActive, domain.AAL1,
		[]domain.AuthMethod{domain.AuthMethodPassword}, domain.DeviceInfo{},
		issued, issued.Add(testAbsTTL), issued.Add(testAbsTTL), testAbsTTL,
		issued, nil, "",
	)
	touchAt := issued.Add(30 * time.Minute) // touchAt + idleTTL(=2h) > absExpiry(=2h)
	if err := s.Touch(touchAt); err != nil {
		t.Fatalf("Touch: %v", err)
	}
	if !s.IdleExpiry().Equal(s.AbsoluteExpiry()) {
		t.Errorf("idleExpiry = %v, want clamped to absExpiry %v", s.IdleExpiry(), s.AbsoluteExpiry())
	}
}

func TestSessionTouchRejectsDeadSessions(t *testing.T) {
	t.Run("revoked", func(t *testing.T) {
		s := mustSession(t)
		if err := s.Revoke(timeFixed().Add(time.Minute), "logout"); err != nil {
			t.Fatal(err)
		}
		if err := s.Touch(timeFixed().Add(2 * time.Minute)); !errors.Is(err, domain.ErrSessionRevoked) {
			t.Errorf("err = %v, want ErrSessionRevoked", err)
		}
	})

	t.Run("expired", func(t *testing.T) {
		s, now := reconstituteExpired(t)
		if err := s.Touch(now); !errors.Is(err, domain.ErrSessionExpired) {
			t.Errorf("err = %v, want ErrSessionExpired", err)
		}
	})
}

// --- Revoke ----------------------------------------------------------------

func TestSessionRevoke(t *testing.T) {
	s := mustSession(t)

	revokedAt := timeFixed().Add(time.Minute)
	if err := s.Revoke(revokedAt, "  user logout  "); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if s.Status() != domain.SessionRevoked {
		t.Errorf("status = %v, want revoked", s.Status())
	}
	if ts, ok := s.RevokedAt(); !ok || !ts.Equal(revokedAt) {
		t.Errorf("revokedAt = %v, want %v", ts, revokedAt)
	}
	if s.Reason() != "user logout" {
		t.Errorf("reason = %q, want trimmed 'user logout'", s.Reason())
	}

	if err := s.Revoke(timeFixed().Add(2*time.Minute), "again"); !errors.Is(err, domain.ErrSessionNotActive) {
		t.Errorf("double revoke err = %v, want ErrSessionNotActive", err)
	}
}

// --- Expire ----------------------------------------------------------------

func TestSessionExpire(t *testing.T) {
	t.Run("active but not yet expired rejected", func(t *testing.T) {
		s := mustSession(t)
		if err := s.Expire(timeFixed().Add(time.Minute)); !errors.Is(err, domain.ErrSessionNotExpired) {
			t.Errorf("err = %v, want ErrSessionNotExpired", err)
		}
	})

	t.Run("revoked session rejected", func(t *testing.T) {
		s := mustSession(t)
		if err := s.Revoke(timeFixed().Add(time.Minute), "logout"); err != nil {
			t.Fatal(err)
		}
		// past a deadline but already non-active: Expire must refuse.
		if err := s.Expire(timeFixed().Add(testAbsTTL + time.Hour)); !errors.Is(err, domain.ErrSessionNotActive) {
			t.Errorf("err = %v, want ErrSessionNotActive", err)
		}
	})

	t.Run("past deadline transitions to expired", func(t *testing.T) {
		s, now := reconstituteExpired(t)
		if err := s.Expire(now); err != nil {
			t.Fatalf("Expire: %v", err)
		}
		if s.Status() != domain.SessionExpired {
			t.Errorf("status = %v, want expired", s.Status())
		}
	})
}

// --- StepUp ----------------------------------------------------------------

func TestSessionStepUp(t *testing.T) {
	t.Run("raise aal1 -> aal2 records method", func(t *testing.T) {
		s := mustSession(t)
		if err := s.StepUp(timeFixed().Add(time.Minute), domain.AAL2, domain.AuthMethodOTP); err != nil {
			t.Fatalf("StepUp: %v", err)
		}
		if s.AuthLevel() != domain.AAL2 {
			t.Errorf("authLevel = %v, want aal2", s.AuthLevel())
		}
		if !s.UsedMethod(domain.AuthMethodOTP) || !s.UsedMethod(domain.AuthMethodPassword) {
			t.Errorf("amr = %v, want pwd+otp", s.AMR())
		}
	})

	t.Run("does not slide idle deadline or lastSeenAt", func(t *testing.T) {
		s := mustSession(t)
		idleBefore := s.IdleExpiry()
		seenBefore := s.LastSeenAt()
		if err := s.StepUp(timeFixed().Add(time.Minute), domain.AAL2, domain.AuthMethodOTP); err != nil {
			t.Fatalf("StepUp: %v", err)
		}
		if !s.IdleExpiry().Equal(idleBefore) {
			t.Errorf("idleExpiry moved on StepUp: %v, want %v", s.IdleExpiry(), idleBefore)
		}
		if !s.LastSeenAt().Equal(seenBefore) {
			t.Errorf("lastSeenAt moved on StepUp: %v, want %v", s.LastSeenAt(), seenBefore)
		}
	})

	t.Run("equal level keeps level, records method, dedupes", func(t *testing.T) {
		s := mustSession(t)
		// pwd already in amr from creation; re-presenting it must not duplicate.
		if err := s.StepUp(timeFixed().Add(time.Minute), domain.AAL1, domain.AuthMethodPassword); err != nil {
			t.Errorf("equal StepUp err = %v, want nil", err)
		}
		if len(s.AMR()) != 1 {
			t.Errorf("amr = %v, want deduped single pwd", s.AMR())
		}
	})

	t.Run("lowering rejected", func(t *testing.T) {
		s := mustSession(t)
		if err := s.StepUp(timeFixed().Add(time.Minute), domain.AAL2, domain.AuthMethodOTP); err != nil {
			t.Fatal(err)
		}
		if err := s.StepUp(timeFixed().Add(2*time.Minute), domain.AAL1, domain.AuthMethodPassword); !errors.Is(err, domain.ErrAALNotRaised) {
			t.Errorf("err = %v, want ErrAALNotRaised", err)
		}
	})

	t.Run("invalid level rejected", func(t *testing.T) {
		s := mustSession(t)
		if err := s.StepUp(timeFixed().Add(time.Minute), domain.AuthLevel(0), domain.AuthMethodOTP); !errors.Is(err, domain.ErrInvalidAuthLevel) {
			t.Errorf("err = %v, want ErrInvalidAuthLevel", err)
		}
	})

	t.Run("invalid method rejected", func(t *testing.T) {
		s := mustSession(t)
		if err := s.StepUp(timeFixed().Add(time.Minute), domain.AAL2, domain.AuthMethod("face")); !errors.Is(err, domain.ErrInvalidAuthMethod) {
			t.Errorf("err = %v, want ErrInvalidAuthMethod", err)
		}
	})

	t.Run("non-active rejected", func(t *testing.T) {
		s := mustSession(t)
		if err := s.Revoke(timeFixed().Add(time.Minute), "x"); err != nil {
			t.Fatal(err)
		}
		if err := s.StepUp(timeFixed().Add(2*time.Minute), domain.AAL2, domain.AuthMethodOTP); !errors.Is(err, domain.ErrSessionNotActive) {
			t.Errorf("err = %v, want ErrSessionNotActive", err)
		}
	})

	t.Run("expired rejected", func(t *testing.T) {
		s, now := reconstituteExpired(t)
		if err := s.StepUp(now, domain.AAL2, domain.AuthMethodOTP); !errors.Is(err, domain.ErrSessionNotActive) {
			t.Errorf("err = %v, want ErrSessionNotActive", err)
		}
	})
}

// --- Reconstitute ----------------------------------------------------------

func TestReconstituteSession(t *testing.T) {
	id := domain.NewSessionID()
	uid := domain.NewUserID()
	hash := mustTokenHash(t, []byte("h"))
	issued := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	revoked := issued.Add(time.Hour)

	s := domain.ReconstituteSession(
		id, uid, hash,
		domain.SessionRevoked, domain.AAL2,
		[]domain.AuthMethod{domain.AuthMethodPassword, domain.AuthMethodOTP},
		domain.DeviceInfo{},
		issued, issued.Add(testAbsTTL), issued.Add(testIdleTTL), testIdleTTL,
		issued, &revoked, "compromised",
	)

	if s.ID() != id || s.UserID() != uid || s.AuthLevel() != domain.AAL2 {
		t.Error("reconstitute did not preserve core fields")
	}
	if !bytes.Equal(s.TokenHash().Bytes(), []byte("h")) {
		t.Errorf("tokenHash = %q, want h", s.TokenHash().Bytes())
	}
	if s.Device() != (domain.DeviceInfo{}) {
		t.Error("reconstitute did not preserve device")
	}
	if !s.UsedMethod(domain.AuthMethodPassword) || !s.UsedMethod(domain.AuthMethodOTP) {
		t.Errorf("reconstitute did not preserve amr: %v", s.AMR())
	}
	if s.Status() != domain.SessionRevoked || s.Reason() != "compromised" {
		t.Error("reconstitute did not preserve status/reason")
	}
	if ts, ok := s.RevokedAt(); !ok || !ts.Equal(revoked) {
		t.Error("reconstitute did not preserve revokedAt")
	}
}

func TestReconstituteSessionIsolatesRevokedAt(t *testing.T) {
	issued := timeFixed()
	revoked := issued.Add(time.Hour)
	s := domain.ReconstituteSession(
		domain.NewSessionID(), domain.NewUserID(), mustTokenHash(t, []byte("h")),
		domain.SessionRevoked, domain.AAL1,
		[]domain.AuthMethod{domain.AuthMethodPassword}, domain.DeviceInfo{},
		issued, issued.Add(testAbsTTL), issued.Add(testIdleTTL), testIdleTTL,
		issued, &revoked, "x",
	)

	// mutating the caller-owned pointee must not move the aggregate's revokedAt.
	revoked = revoked.Add(-100 * time.Hour)
	if ts, ok := s.RevokedAt(); !ok || !ts.Equal(issued.Add(time.Hour)) {
		t.Errorf("revokedAt aliased caller pointer: got %v after mutation", ts)
	}
}

// reconstituteExpired returns an active-status session whose deadlines are in
// the past relative to the returned now, so time-derived expiry fires without
// controlling the wall clock.
func reconstituteExpired(t *testing.T) (*domain.Session, time.Time) {
	t.Helper()
	now := timeFixed()
	past := now.Add(-testAbsTTL - time.Hour)
	s := domain.ReconstituteSession(
		domain.NewSessionID(), domain.NewUserID(), mustTokenHash(t, []byte("h")),
		domain.SessionActive, domain.AAL1,
		[]domain.AuthMethod{domain.AuthMethodPassword}, domain.DeviceInfo{},
		past, past.Add(testAbsTTL), past.Add(testIdleTTL), testIdleTTL,
		past, nil, "",
	)
	return s, now
}
