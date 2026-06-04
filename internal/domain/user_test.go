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
	u, err := domain.NewUser(mustEmail(t, "user@example.com"), roles...)
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
		if !u.CreatedAt().Equal(u.UpdatedAt()) {
			t.Error("createdAt and updatedAt should match on creation")
		}
		if _, ok := u.Phone(); ok {
			t.Error("new user should have no phone")
		}
	})

	t.Run("empty email rejected", func(t *testing.T) {
		if _, err := domain.NewUser(domain.Email{}); !errors.Is(err, domain.ErrEmailRequired) {
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
		_, err := domain.NewUser(mustEmail(t, "a@b.com"), domain.Role("superuser"))
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
	before := u.UpdatedAt()

	if err := u.VerifyEmail(); err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}
	if !u.EmailVerified() {
		t.Error("email not marked verified")
	}
	if u.Status() != domain.StatusActive {
		t.Errorf("status = %v, want active (auto-promote)", u.Status())
	}
	if u.UpdatedAt().Before(before) {
		t.Error("updatedAt went backwards")
	}

	if err := u.VerifyEmail(); !errors.Is(err, domain.ErrEmailAlreadyVerified) {
		t.Errorf("second verify err = %v, want ErrEmailAlreadyVerified", err)
	}
}

func TestVerifyEmailDoesNotPromoteNonPending(t *testing.T) {
	u := mustUser(t)
	if err := u.VerifyEmail(); err != nil { // pending -> active
		t.Fatal(err)
	}
	if err := u.Suspend(); err != nil { // active -> suspended
		t.Fatal(err)
	}
	// changing email resets verification; re-verifying must not resurrect to active
	if err := u.ChangeEmail(mustEmail(t, "new@example.com")); err != nil {
		t.Fatal(err)
	}
	if err := u.VerifyEmail(); err != nil {
		t.Fatal(err)
	}
	if u.Status() != domain.StatusSuspended {
		t.Errorf("status = %v, want suspended (no promote from non-pending)", u.Status())
	}
}

// --- ChangeEmail -----------------------------------------------------------

func TestChangeEmail(t *testing.T) {
	u := mustUser(t)
	if err := u.VerifyEmail(); err != nil {
		t.Fatal(err)
	}

	if err := u.ChangeEmail(mustEmail(t, "fresh@example.com")); err != nil {
		t.Fatalf("ChangeEmail: %v", err)
	}
	if u.Email().String() != "fresh@example.com" {
		t.Errorf("email = %q, want fresh@example.com", u.Email())
	}
	if u.EmailVerified() {
		t.Error("verification not reset after email change")
	}

	if err := u.ChangeEmail(domain.Email{}); !errors.Is(err, domain.ErrEmailRequired) {
		t.Errorf("err = %v, want ErrEmailRequired", err)
	}
}

// --- Phone -----------------------------------------------------------------

func TestPhoneLifecycle(t *testing.T) {
	u := mustUser(t)

	if err := u.VerifyPhone(); !errors.Is(err, domain.ErrPhoneNotSet) {
		t.Errorf("verify before set err = %v, want ErrPhoneNotSet", err)
	}

	phone, _ := domain.NewPhone("+14155552671")
	if err := u.SetPhone(phone); err != nil {
		t.Fatalf("SetPhone: %v", err)
	}
	got, ok := u.Phone()
	if !ok || got.String() != "+14155552671" {
		t.Errorf("Phone() = %q, %v", got, ok)
	}
	if u.PhoneVerified() {
		t.Error("phone should be unverified after SetPhone")
	}

	if err := u.VerifyPhone(); err != nil {
		t.Fatalf("VerifyPhone: %v", err)
	}
	if !u.PhoneVerified() {
		t.Error("phone not verified")
	}
	if err := u.VerifyPhone(); !errors.Is(err, domain.ErrPhoneAlreadyVerified) {
		t.Errorf("re-verify err = %v, want ErrPhoneAlreadyVerified", err)
	}

	// replacing phone resets verification
	other, _ := domain.NewPhone("+491701234567")
	if err := u.SetPhone(other); err != nil {
		t.Fatal(err)
	}
	if u.PhoneVerified() {
		t.Error("verification not reset after phone replace")
	}

	if err := u.SetPhone(domain.Phone{}); !errors.Is(err, domain.ErrInvalidPhone) {
		t.Errorf("set zero phone err = %v, want ErrInvalidPhone", err)
	}
}

// --- Status transitions ----------------------------------------------------

func TestStatusTransitions(t *testing.T) {
	type step struct {
		action  func(*domain.User) error
		want    domain.Status
		wantErr error
	}
	activate := func(u *domain.User) error { return u.Activate() }
	suspend := func(u *domain.User) error { return u.Suspend() }
	deactivate := func(u *domain.User) error { return u.Deactivate() }

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

	if err := u.AddRole(domain.RoleAdmin); err != nil {
		t.Fatalf("AddRole: %v", err)
	}
	if !u.HasRole(domain.RoleAdmin) {
		t.Error("admin role not added")
	}

	// adding existing role is a no-op, no duplicate
	if err := u.AddRole(domain.RoleAdmin); err != nil {
		t.Fatalf("AddRole(dup): %v", err)
	}
	if len(u.Roles()) != 2 {
		t.Errorf("roles = %v, want 2", u.Roles())
	}

	if err := u.AddRole(domain.Role("bogus")); !errors.Is(err, domain.ErrInvalidRole) {
		t.Errorf("err = %v, want ErrInvalidRole", err)
	}

	if err := u.RemoveRole(domain.RoleAdmin); err != nil {
		t.Fatalf("RemoveRole: %v", err)
	}
	if u.HasRole(domain.RoleAdmin) {
		t.Error("admin role not removed")
	}

	if err := u.RemoveRole(domain.RoleAdmin); !errors.Is(err, domain.ErrRoleNotAssigned) {
		t.Errorf("err = %v, want ErrRoleNotAssigned", err)
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
