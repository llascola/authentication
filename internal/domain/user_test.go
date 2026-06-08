package domain_test

import (
	"errors"
	"testing"
	"time"

	"authentication/internal/domain"
)

func timeFixed() time.Time {
	return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
}

// later returns the fixed base time advanced by d, for asserting that a mutator
// stamped the exact instant it was given.
func later(d time.Duration) time.Time { return timeFixed().Add(d) }

// --- helpers ---------------------------------------------------------------

func mustEmail(t *testing.T, raw string) domain.Email {
	t.Helper()
	e, err := domain.NewEmail(raw)
	if err != nil {
		t.Fatalf("NewEmail(%q): unexpected error: %v", raw, err)
	}
	return e
}

func mustUser(t *testing.T, roles ...domain.Role) *domain.User {
	t.Helper()
	u, err := domain.NewUser(timeFixed(), mustEmail(t, "user@example.com"), roles...)
	if err != nil {
		t.Fatalf("NewUser: unexpected error: %v", err)
	}
	return u
}

// --- Email -----------------------------------------------------------------

func TestNewEmail(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    string // normalised form; "" when error expected
		wantErr error
	}{
		{"normalises case+space", "  User@Example.COM ", "user@example.com", nil},
		{"empty", "", "", domain.ErrEmailRequired},
		{"blank", "   ", "", domain.ErrEmailRequired},
		{"no at", "userexample.com", "", domain.ErrInvalidEmail},
		{"display name rejected", "Bob <bob@example.com>", "", domain.ErrInvalidEmail},
		{"trailing junk", "a@b.com x", "", domain.ErrInvalidEmail},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := domain.NewEmail(tc.raw)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr == nil && got.String() != tc.want {
				t.Errorf("normalised = %q, want %q", got.String(), tc.want)
			}
		})
	}
}

// --- Phone -----------------------------------------------------------------

func TestNewPhone(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{"valid e164", "+14155552671", false},
		{"valid trimmed", "  +491701234567 ", false},
		{"missing plus", "14155552671", true},
		{"leading zero", "+0455552671", true},
		{"contains letters", "+1415555ABCD", true},
		{"too long", "+1234567890123456", true},
		{"empty", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := domain.NewPhone(tc.raw)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tc.wantErr)
			}
			if tc.wantErr && !errors.Is(err, domain.ErrInvalidPhone) {
				t.Errorf("err = %v, want ErrInvalidPhone", err)
			}
		})
	}
}

// --- UserID ----------------------------------------------------------------

func TestUserID(t *testing.T) {
	id := domain.NewUserID()
	if id.IsZero() {
		t.Fatal("NewUserID returned zero id")
	}

	parsed, err := domain.ParseUserID(id.String())
	if err != nil {
		t.Fatalf("ParseUserID round-trip: %v", err)
	}
	if parsed != id {
		t.Errorf("round-trip = %v, want %v", parsed, id)
	}

	if _, err := domain.ParseUserID("not-a-uuid"); !errors.Is(err, domain.ErrInvalidUserID) {
		t.Errorf("err = %v, want ErrInvalidUserID", err)
	}
	if !(domain.UserID{}).IsZero() {
		t.Error("zero UserID should report IsZero")
	}
}

// --- Status ----------------------------------------------------------------

func TestStatusString(t *testing.T) {
	tests := map[domain.Status]string{
		domain.StatusPending:     "pending",
		domain.StatusActive:      "active",
		domain.StatusSuspended:   "suspended",
		domain.StatusDeactivated: "deactivated",
		domain.Status(99):        "unknown",
	}
	for s, want := range tests {
		if got := s.String(); got != want {
			t.Errorf("Status(%d).String() = %q, want %q", s, got, want)
		}
	}
}

func TestStatusValid(t *testing.T) {
	for _, s := range []domain.Status{
		domain.StatusPending, domain.StatusActive, domain.StatusSuspended, domain.StatusDeactivated,
	} {
		if !s.Valid() {
			t.Errorf("Status(%d) should be valid", s)
		}
	}
	if domain.Status(99).Valid() {
		t.Error("out-of-range status reported valid")
	}
}

// --- NewUser ---------------------------------------------------------------

func TestNewUser(t *testing.T) {
	t.Run("defaults to pending with RoleUser", func(t *testing.T) {
		u := mustUser(t)
		if u.ID().IsZero() {
			t.Error("id not set")
		}
		if u.Status() != domain.StatusPending {
			t.Errorf("status = %v, want pending", u.Status())
		}
		if u.EmailVerified() {
			t.Error("new user should be unverified")
		}
		if roles := u.Roles(); len(roles) != 1 || roles[0] != domain.RoleUser {
			t.Errorf("roles = %v, want [user]", roles)
		}
		// timestamps are exactly the creation instant we passed.
		if !u.CreatedAt().Equal(timeFixed()) || !u.UpdatedAt().Equal(timeFixed()) {
			t.Errorf("timestamps = (%v, %v), want both %v", u.CreatedAt(), u.UpdatedAt(), timeFixed())
		}
		if _, ok := u.Phone(); ok {
			t.Error("new user should have no phone")
		}
	})

	t.Run("empty email rejected", func(t *testing.T) {
		if _, err := domain.NewUser(timeFixed(), domain.Email{}); !errors.Is(err, domain.ErrEmailRequired) {
			t.Errorf("err = %v, want ErrEmailRequired", err)
		}
	})

	t.Run("dedupes roles", func(t *testing.T) {
		u := mustUser(t, domain.RoleAdmin, domain.RoleUser, domain.RoleAdmin)
		if got := u.Roles(); len(got) != 2 {
			t.Errorf("roles = %v, want 2 unique", got)
		}
	})

	t.Run("invalid role rejected", func(t *testing.T) {
		_, err := domain.NewUser(timeFixed(), mustEmail(t, "a@b.com"), domain.Role("superuser"))
		if !errors.Is(err, domain.ErrInvalidRole) {
			t.Errorf("err = %v, want ErrInvalidRole", err)
		}
	})
}

// --- Roles getter isolation ------------------------------------------------

func TestRolesGetterIsCopy(t *testing.T) {
	u := mustUser(t)
	roles := u.Roles()
	roles[0] = domain.RoleAdmin // mutate returned slice
	if u.HasRole(domain.RoleAdmin) {
		t.Error("mutating returned slice leaked into aggregate")
	}
}

// --- Email verification ----------------------------------------------------

func TestVerifyEmail(t *testing.T) {
	u := mustUser(t)

	verifiedAt := later(time.Hour)
	if err := u.VerifyEmail(verifiedAt); err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}
	if !u.EmailVerified() {
		t.Error("email not marked verified")
	}
	if u.Status() != domain.StatusActive {
		t.Errorf("status = %v, want active (auto-promote)", u.Status())
	}
	// the mutator stamped exactly the instant it was given.
	if !u.UpdatedAt().Equal(verifiedAt) {
		t.Errorf("updatedAt = %v, want %v", u.UpdatedAt(), verifiedAt)
	}

	if err := u.VerifyEmail(later(2 * time.Hour)); !errors.Is(err, domain.ErrEmailAlreadyVerified) {
		t.Errorf("second verify err = %v, want ErrEmailAlreadyVerified", err)
	}
}

func TestVerifyEmailDoesNotPromoteNonPending(t *testing.T) {
	u := mustUser(t)
	if err := u.VerifyEmail(later(time.Hour)); err != nil { // pending -> active
		t.Fatal(err)
	}
	if err := u.Suspend(later(2 * time.Hour)); err != nil { // active -> suspended
		t.Fatal(err)
	}
	// changing email resets verification; re-verifying must not resurrect to active
	if err := u.ChangeEmail(later(3*time.Hour), mustEmail(t, "new@example.com")); err != nil {
		t.Fatal(err)
	}
	if err := u.VerifyEmail(later(4 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	if u.Status() != domain.StatusSuspended {
		t.Errorf("status = %v, want suspended (no promote from non-pending)", u.Status())
	}
}

// --- ChangeEmail -----------------------------------------------------------

func TestChangeEmail(t *testing.T) {
	u := mustUser(t)
	if err := u.VerifyEmail(later(time.Hour)); err != nil {
		t.Fatal(err)
	}

	changedAt := later(2 * time.Hour)
	if err := u.ChangeEmail(changedAt, mustEmail(t, "fresh@example.com")); err != nil {
		t.Fatalf("ChangeEmail: %v", err)
	}
	if u.Email().String() != "fresh@example.com" {
		t.Errorf("email = %q, want fresh@example.com", u.Email())
	}
	if u.EmailVerified() {
		t.Error("verification not reset after email change")
	}
	if !u.UpdatedAt().Equal(changedAt) {
		t.Errorf("updatedAt = %v, want %v", u.UpdatedAt(), changedAt)
	}

	if err := u.ChangeEmail(later(3*time.Hour), domain.Email{}); !errors.Is(err, domain.ErrEmailRequired) {
		t.Errorf("err = %v, want ErrEmailRequired", err)
	}
}

// Resubmitting the current email is not a no-op: it resets verification. Pins
// the deliberate behaviour so any move to a same-value short-circuit is a
// conscious change, not a silent regression.
// Re-submitting the current email is rejected with ErrEmailUnchanged and must
// NOT drop the verified flag — a no-op change cannot un-verify a proven address.
func TestChangeEmailToSameValueRejected(t *testing.T) {
	u := mustUser(t)
	if err := u.VerifyEmail(later(time.Hour)); err != nil {
		t.Fatal(err)
	}
	same := u.Email()
	if err := u.ChangeEmail(later(2*time.Hour), same); !errors.Is(err, domain.ErrEmailUnchanged) {
		t.Fatalf("ChangeEmail(same) err = %v, want ErrEmailUnchanged", err)
	}
	if !u.EmailVerified() {
		t.Error("verification dropped despite rejected no-op change")
	}
}

// --- Phone -----------------------------------------------------------------

func TestPhoneLifecycle(t *testing.T) {
	u := mustUser(t)

	if err := u.VerifyPhone(later(time.Hour)); !errors.Is(err, domain.ErrPhoneNotSet) {
		t.Errorf("verify before set err = %v, want ErrPhoneNotSet", err)
	}

	phone, _ := domain.NewPhone("+14155552671")
	setAt := later(time.Hour)
	if err := u.SetPhone(setAt, phone); err != nil {
		t.Fatalf("SetPhone: %v", err)
	}
	if !u.UpdatedAt().Equal(setAt) {
		t.Errorf("updatedAt = %v, want %v", u.UpdatedAt(), setAt)
	}
	got, ok := u.Phone()
	if !ok || got.String() != "+14155552671" {
		t.Errorf("Phone() = %q, %v", got, ok)
	}
	if u.PhoneVerified() {
		t.Error("phone should be unverified after SetPhone")
	}

	if err := u.VerifyPhone(later(2 * time.Hour)); err != nil {
		t.Fatalf("VerifyPhone: %v", err)
	}
	if !u.PhoneVerified() {
		t.Error("phone not verified")
	}
	if err := u.VerifyPhone(later(3 * time.Hour)); !errors.Is(err, domain.ErrPhoneAlreadyVerified) {
		t.Errorf("re-verify err = %v, want ErrPhoneAlreadyVerified", err)
	}

	// replacing phone resets verification
	other, _ := domain.NewPhone("+491701234567")
	if err := u.SetPhone(later(4*time.Hour), other); err != nil {
		t.Fatal(err)
	}
	if u.PhoneVerified() {
		t.Error("verification not reset after phone replace")
	}

	if err := u.SetPhone(later(5*time.Hour), domain.Phone{}); !errors.Is(err, domain.ErrInvalidPhone) {
		t.Errorf("set zero phone err = %v, want ErrInvalidPhone", err)
	}
}

// SetPhone to the current number is rejected with ErrPhoneUnchanged and must NOT
// drop the verified flag, mirroring TestChangeEmailToSameValueRejected.
func TestSetPhoneToSameValueRejected(t *testing.T) {
	u := mustUser(t)
	phone, _ := domain.NewPhone("+14155552671")
	if err := u.SetPhone(later(time.Hour), phone); err != nil {
		t.Fatal(err)
	}
	if err := u.VerifyPhone(later(2 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := u.SetPhone(later(3*time.Hour), phone); !errors.Is(err, domain.ErrPhoneUnchanged) { // same number
		t.Fatalf("SetPhone(same) err = %v, want ErrPhoneUnchanged", err)
	}
	if !u.PhoneVerified() {
		t.Error("verification dropped despite rejected no-op change")
	}
}

// --- Status transitions ----------------------------------------------------

func TestStatusTransitions(t *testing.T) {
	type step struct {
		action  func(*domain.User) error
		want    domain.Status
		wantErr error
	}
	activate := func(u *domain.User) error { return u.Activate(timeFixed()) }
	suspend := func(u *domain.User) error { return u.Suspend(timeFixed()) }
	deactivate := func(u *domain.User) error { return u.Deactivate(timeFixed()) }

	tests := []struct {
		name  string
		steps []step
	}{
		{"pending->active", []step{{activate, domain.StatusActive, nil}}},
		{"pending->deactivated", []step{{deactivate, domain.StatusDeactivated, nil}}},
		{"active->suspended->active", []step{
			{activate, domain.StatusActive, nil},
			{suspend, domain.StatusSuspended, nil},
			{activate, domain.StatusActive, nil},
		}},
		{"pending->suspended illegal", []step{
			{suspend, domain.StatusPending, domain.ErrStatusTransition},
		}},
		{"deactivated is terminal", []step{
			{deactivate, domain.StatusDeactivated, nil},
			{activate, domain.StatusDeactivated, domain.ErrStatusTransition},
		}},
		{"same-state is noop", []step{
			{activate, domain.StatusActive, nil},
			{activate, domain.StatusActive, nil}, // active->active, no error
		}},
		{"suspended->suspended noop", []step{
			{activate, domain.StatusActive, nil},
			{suspend, domain.StatusSuspended, nil},
			{suspend, domain.StatusSuspended, nil}, // suspended->suspended, no error
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			u := mustUser(t)
			for i, s := range tc.steps {
				err := s.action(u)
				if !errors.Is(err, s.wantErr) {
					t.Fatalf("step %d: err = %v, want %v", i, err, s.wantErr)
				}
				if u.Status() != s.want {
					t.Fatalf("step %d: status = %v, want %v", i, u.Status(), s.want)
				}
			}
		})
	}
}

// --- Roles -----------------------------------------------------------------

func TestRoleManagement(t *testing.T) {
	u := mustUser(t) // starts [user]

	if err := u.AddRole(later(time.Hour), domain.RoleAdmin); err != nil {
		t.Fatalf("AddRole: %v", err)
	}
	if !u.HasRole(domain.RoleAdmin) {
		t.Error("admin role not added")
	}
	if !u.UpdatedAt().Equal(later(time.Hour)) {
		t.Errorf("updatedAt = %v, want %v", u.UpdatedAt(), later(time.Hour))
	}

	// adding existing role is a no-op, no duplicate
	if err := u.AddRole(later(2*time.Hour), domain.RoleAdmin); err != nil {
		t.Fatalf("AddRole(dup): %v", err)
	}
	if len(u.Roles()) != 2 {
		t.Errorf("roles = %v, want 2", u.Roles())
	}

	if err := u.AddRole(later(2*time.Hour), domain.Role("bogus")); !errors.Is(err, domain.ErrInvalidRole) {
		t.Errorf("err = %v, want ErrInvalidRole", err)
	}

	if err := u.RemoveRole(later(3*time.Hour), domain.RoleAdmin); err != nil {
		t.Fatalf("RemoveRole: %v", err)
	}
	if u.HasRole(domain.RoleAdmin) {
		t.Error("admin role not removed")
	}

	if err := u.RemoveRole(later(4*time.Hour), domain.RoleAdmin); !errors.Is(err, domain.ErrRoleNotAssigned) {
		t.Errorf("err = %v, want ErrRoleNotAssigned", err)
	}
}

// Removing the last remaining role is rejected: a User always keeps >=1 role.
func TestRemoveLastRoleRejected(t *testing.T) {
	u := mustUser(t) // defaults to {RoleUser}
	if got := u.Roles(); len(got) != 1 {
		t.Fatalf("roles = %v, want exactly 1", got)
	}
	if err := u.RemoveRole(later(time.Hour), domain.RoleUser); !errors.Is(err, domain.ErrCannotRemoveLastRole) {
		t.Fatalf("err = %v, want ErrCannotRemoveLastRole", err)
	}
	if !u.HasRole(domain.RoleUser) {
		t.Error("role removed despite rejection")
	}
}

// --- Lockout ---------------------------------------------------------------

func TestUserLockout(t *testing.T) {
	t.Run("failed logins increment counter", func(t *testing.T) {
		u := mustUser(t)
		u.RecordFailedLogin(later(time.Minute))
		u.RecordFailedLogin(later(2 * time.Minute))
		if u.FailedAttempts() != 2 {
			t.Errorf("failedAttempts = %d, want 2", u.FailedAttempts())
		}
		if _, locked := u.LockedUntil(); locked {
			t.Error("should not be locked below threshold")
		}
	})

	t.Run("threshold locks for exactly lockoutDuration and resets counter", func(t *testing.T) {
		u := mustUser(t)
		var lockAt time.Time
		for i := range 5 { // maxFailedLogins
			lockAt = later(time.Duration(i) * time.Minute)
			u.RecordFailedLogin(lockAt)
		}
		if u.FailedAttempts() != 0 {
			t.Errorf("counter not reset on lock: %d", u.FailedAttempts())
		}
		until, ok := u.LockedUntil()
		if !ok {
			t.Fatal("lockedUntil not set after threshold")
		}
		// lock deadline is exactly the locking instant + 15m (lockoutDuration).
		wantUntil := lockAt.Add(15 * time.Minute)
		if !until.Equal(wantUntil) {
			t.Errorf("lockedUntil = %v, want %v", until, wantUntil)
		}
		// locked strictly before the deadline, unlocked at and after it.
		if !u.IsLocked(wantUntil.Add(-time.Second)) {
			t.Error("should be locked one second before deadline")
		}
		if u.IsLocked(wantUntil) {
			t.Error("should be unlocked exactly at deadline (Before is strict)")
		}
		if u.IsLocked(wantUntil.Add(time.Second)) {
			t.Error("should be unlocked after deadline")
		}
	})

	t.Run("re-locks after a fresh window of failures", func(t *testing.T) {
		u := mustUser(t)
		for i := range 5 {
			u.RecordFailedLogin(later(time.Duration(i) * time.Minute))
		}
		first, _ := u.LockedUntil()
		// counter reset to 0 on lock; a fresh batch must lock again at a new deadline.
		for i := range 5 {
			u.RecordFailedLogin(later(time.Hour + time.Duration(i)*time.Minute))
		}
		second, ok := u.LockedUntil()
		if !ok || !second.After(first) {
			t.Errorf("re-lock deadline = %v, want after first %v", second, first)
		}
	})

	t.Run("failures during an active lock extend the deadline", func(t *testing.T) {
		u := mustUser(t)
		for i := range 5 { // first lock
			u.RecordFailedLogin(later(time.Duration(i) * time.Minute))
		}
		first, ok := u.LockedUntil()
		if !ok {
			t.Fatal("not locked after first window")
		}
		// counter reset to 0 on lock; recording more failures while still locked
		// walks it back up and re-locks at a later deadline (self-extension).
		for i := range 5 {
			u.RecordFailedLogin(first.Add(-time.Minute + time.Duration(i)*time.Second))
		}
		second, ok := u.LockedUntil()
		if !ok || !second.After(first) {
			t.Errorf("re-lock during active lock = %v, want after first %v", second, first)
		}
		if u.FailedAttempts() != 0 {
			t.Errorf("counter not reset on re-lock: %d", u.FailedAttempts())
		}
	})

	t.Run("successful login clears counter and lock", func(t *testing.T) {
		u := mustUser(t)
		for i := range 5 {
			u.RecordFailedLogin(later(time.Duration(i) * time.Minute))
		}
		u.RecordSuccessfulLogin(later(time.Hour))
		if u.IsLocked(later(time.Hour)) {
			t.Error("still locked after successful login")
		}
		if u.FailedAttempts() != 0 {
			t.Errorf("counter not cleared: %d", u.FailedAttempts())
		}
		if _, ok := u.LockedUntil(); ok {
			t.Error("lockedUntil not cleared")
		}
	})
}

func TestUserIsLockedAutoExpires(t *testing.T) {
	// reconstitute a user whose lock deadline is in the past: reads as unlocked
	// without any mutation, exercising the time-derived auto-unlock.
	past := timeFixed().Add(-time.Hour)
	u := domain.Reconstitute(
		domain.NewUserID(), mustEmail(t, "locked@example.com"),
		true, nil, false, domain.StatusActive, []domain.Role{domain.RoleUser},
		false, 0, &past,
		timeFixed(), timeFixed(),
	)
	if u.IsLocked(timeFixed()) {
		t.Error("expired lock should read as unlocked")
	}
	// boundary: exactly at the deadline is no longer locked (Before is strict).
	if u.IsLocked(past) {
		t.Error("at-deadline should read as unlocked")
	}
}

// --- MFA -------------------------------------------------------------------

func TestUserEnableMFA(t *testing.T) {
	t.Run("enables with a confirmed factor", func(t *testing.T) {
		u := mustUser(t)
		enabledAt := later(time.Hour)
		if err := u.EnableMFA(enabledAt, true); err != nil {
			t.Fatalf("EnableMFA: %v", err)
		}
		if !u.MFAEnabled() {
			t.Error("mfa not enabled")
		}
		if !u.UpdatedAt().Equal(enabledAt) {
			t.Errorf("updatedAt = %v, want %v", u.UpdatedAt(), enabledAt)
		}
	})

	t.Run("rejected without a confirmed factor", func(t *testing.T) {
		u := mustUser(t)
		if err := u.EnableMFA(later(time.Hour), false); !errors.Is(err, domain.ErrNoConfirmedFactor) {
			t.Errorf("err = %v, want ErrNoConfirmedFactor", err)
		}
		if u.MFAEnabled() {
			t.Error("mfa enabled despite no factor")
		}
	})

	t.Run("idempotent when already enabled", func(t *testing.T) {
		u := mustUser(t)
		if err := u.EnableMFA(later(time.Hour), true); err != nil {
			t.Fatal(err)
		}
		// second call needs no factor proof and must not error.
		if err := u.EnableMFA(later(2*time.Hour), false); err != nil {
			t.Errorf("re-enable err = %v, want nil", err)
		}
		if !u.MFAEnabled() {
			t.Error("mfa should stay enabled")
		}
	})
}

func TestUserDisableMFA(t *testing.T) {
	t.Run("disables an enabled account", func(t *testing.T) {
		u := mustUser(t)
		if err := u.EnableMFA(later(time.Hour), true); err != nil {
			t.Fatal(err)
		}
		disabledAt := later(2 * time.Hour)
		u.DisableMFA(disabledAt)
		if u.MFAEnabled() {
			t.Error("mfa not disabled")
		}
		if !u.UpdatedAt().Equal(disabledAt) {
			t.Errorf("updatedAt = %v, want %v", u.UpdatedAt(), disabledAt)
		}
	})

	t.Run("idempotent when already disabled", func(t *testing.T) {
		u := mustUser(t)
		u.DisableMFA(later(time.Hour)) // no-op, must not panic
		if u.MFAEnabled() {
			t.Error("mfa should remain disabled")
		}
	})
}

// --- Terminal-status guard -------------------------------------------------

// A deactivated account is terminal: identity, contact, role, and MFA mutators
// must refuse with ErrUserDeactivated and leave state untouched. Void mutators
// (DisableMFA, RecordFailed/SuccessfulLogin) are deliberately not guarded and
// are excluded here.
func TestMutatorsRejectedOnDeactivated(t *testing.T) {
	deactivated := func(t *testing.T) *domain.User {
		t.Helper()
		u := mustUser(t) // pending
		if err := u.Deactivate(later(time.Hour)); err != nil {
			t.Fatalf("Deactivate: %v", err)
		}
		return u
	}

	phone, _ := domain.NewPhone("+14155552671")

	mutators := map[string]func(*domain.User) error{
		"ChangeEmail": func(u *domain.User) error { return u.ChangeEmail(later(2*time.Hour), mustEmail(t, "new@example.com")) },
		"VerifyEmail": func(u *domain.User) error { return u.VerifyEmail(later(2 * time.Hour)) },
		"SetPhone":    func(u *domain.User) error { return u.SetPhone(later(2*time.Hour), phone) },
		"VerifyPhone": func(u *domain.User) error { return u.VerifyPhone(later(2 * time.Hour)) },
		"AddRole":     func(u *domain.User) error { return u.AddRole(later(2*time.Hour), domain.RoleAdmin) },
		"RemoveRole":  func(u *domain.User) error { return u.RemoveRole(later(2*time.Hour), domain.RoleUser) },
		"EnableMFA":   func(u *domain.User) error { return u.EnableMFA(later(2*time.Hour), true) },
	}

	for name, mutate := range mutators {
		t.Run(name, func(t *testing.T) {
			u := deactivated(t)
			if err := mutate(u); !errors.Is(err, domain.ErrUserDeactivated) {
				t.Fatalf("err = %v, want ErrUserDeactivated", err)
			}
			// state untouched: still the original identity, no side effects.
			if u.Status() != domain.StatusDeactivated {
				t.Errorf("status = %v, want deactivated", u.Status())
			}
			if u.Email().String() != "user@example.com" {
				t.Errorf("email mutated: %q", u.Email())
			}
			if u.EmailVerified() {
				t.Error("email verified despite rejection")
			}
			if _, ok := u.Phone(); ok {
				t.Error("phone set despite rejection")
			}
			if u.HasRole(domain.RoleAdmin) || !u.HasRole(domain.RoleUser) {
				t.Errorf("roles mutated: %v", u.Roles())
			}
			if u.MFAEnabled() {
				t.Error("mfa enabled despite rejection")
			}
		})
	}
}

// --- Reconstitute ----------------------------------------------------------

func TestReconstitute(t *testing.T) {
	id := domain.NewUserID()
	phone, _ := domain.NewPhone("+14155552671")
	roles := []domain.Role{domain.RoleAdmin}

	u := domain.Reconstitute(
		id,
		mustEmail(t, "rehydrated@example.com"),
		true,
		&phone,
		true,
		domain.StatusActive,
		roles,
		false, 0, nil,
		timeFixed(), timeFixed(),
	)

	if u.ID() != id || !u.EmailVerified() || u.Status() != domain.StatusActive {
		t.Error("reconstitute did not preserve state")
	}
	if got, ok := u.Phone(); !ok || got != phone {
		t.Error("phone not preserved")
	}

	// internal roles slice must be a clone of the input
	roles[0] = domain.RoleUser
	if !u.HasRole(domain.RoleAdmin) {
		t.Error("Reconstitute did not clone roles slice")
	}
}

func TestReconstituteIsolatesOptionalPointers(t *testing.T) {
	phone, _ := domain.NewPhone("+14155552671")
	lock := timeFixed().Add(time.Hour)

	u := domain.Reconstitute(
		domain.NewUserID(), mustEmail(t, "a@b.com"),
		true, &phone, true, domain.StatusActive,
		[]domain.Role{domain.RoleUser}, false, 0, &lock,
		timeFixed(), timeFixed(),
	)

	// Mutate the caller-owned variables whose addresses were handed in. A clone
	// inside Reconstitute means the aggregate keeps the values it was built with.
	other, _ := domain.NewPhone("+491701234567")
	phone = other
	lock = lock.Add(-100 * time.Hour)

	if got, ok := u.Phone(); !ok || got.String() != "+14155552671" {
		t.Errorf("phone aliased caller pointer: got %v after mutation", got)
	}
	if until, ok := u.LockedUntil(); !ok || !until.Equal(timeFixed().Add(time.Hour)) {
		t.Errorf("lockedUntil aliased caller pointer: got %v after mutation", until)
	}
}
