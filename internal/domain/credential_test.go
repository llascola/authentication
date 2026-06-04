package domain_test

import (
	"bytes"
	"errors"
	"testing"

	"authentication/internal/domain"
)

// Compile-time proof that every concrete credential satisfies the sealed
// Credential interface. If a type stops implementing it, the package fails to
// build — a cheaper signal than any runtime test.
var (
	_ domain.Credential = (*domain.PasswordCredential)(nil)
	_ domain.Credential = (*domain.OAuthCredential)(nil)
	_ domain.Credential = (*domain.OTPCredential)(nil)
)

// --- helpers ---------------------------------------------------------------

func mustUserID(t *testing.T) domain.UserID {
	t.Helper()
	return domain.NewUserID()
}

func mustPasswordHash(t *testing.T, b []byte) domain.PasswordHash {
	t.Helper()
	h, err := domain.NewPasswordHash(b)
	if err != nil {
		t.Fatalf("NewPasswordHash: unexpected error: %v", err)
	}
	return h
}

func mustTOTPSecret(t *testing.T, b []byte) domain.TOTPSecret {
	t.Helper()
	s, err := domain.NewTOTPSecret(b)
	if err != nil {
		t.Fatalf("NewTOTPSecret: unexpected error: %v", err)
	}
	return s
}

// --- CredentialID ----------------------------------------------------------

func TestCredentialID(t *testing.T) {
	id := domain.NewCredentialID()
	if id.IsZero() {
		t.Fatal("NewCredentialID returned zero id")
	}

	parsed, err := domain.ParseCredentialID(id.String())
	if err != nil {
		t.Fatalf("ParseCredentialID round-trip: %v", err)
	}
	if parsed != id {
		t.Errorf("round-trip = %v, want %v", parsed, id)
	}

	if _, err := domain.ParseCredentialID("nope"); !errors.Is(err, domain.ErrInvalidCredentialID) {
		t.Errorf("err = %v, want ErrInvalidCredentialID", err)
	}
	if !(domain.CredentialID{}).IsZero() {
		t.Error("zero CredentialID should report IsZero")
	}
}

// --- CredentialType / Provider ---------------------------------------------

func TestCredentialTypeValid(t *testing.T) {
	valid := []domain.CredentialType{
		domain.CredentialPassword, domain.CredentialOAuth, domain.CredentialOTP,
	}
	for _, ct := range valid {
		if !ct.Valid() {
			t.Errorf("%q should be valid", ct)
		}
	}
	if domain.CredentialType("magic").Valid() {
		t.Error("unknown type reported valid")
	}
}

func TestProviderValid(t *testing.T) {
	for _, p := range []domain.Provider{domain.ProviderGoogle, domain.ProviderGitHub} {
		if !p.Valid() {
			t.Errorf("%q should be valid", p)
		}
	}
	if domain.Provider("myspace").Valid() {
		t.Error("unknown provider reported valid")
	}
}

// --- PasswordHash (value object) -------------------------------------------

func TestNewPasswordHash(t *testing.T) {
	if _, err := domain.NewPasswordHash(nil); !errors.Is(err, domain.ErrEmptyPasswordHash) {
		t.Errorf("nil err = %v, want ErrEmptyPasswordHash", err)
	}
	if _, err := domain.NewPasswordHash([]byte{}); !errors.Is(err, domain.ErrEmptyPasswordHash) {
		t.Errorf("empty err = %v, want ErrEmptyPasswordHash", err)
	}

	h := mustPasswordHash(t, []byte("hashed"))
	if h.IsZero() {
		t.Error("non-empty hash reports IsZero")
	}
	if !bytes.Equal(h.Bytes(), []byte("hashed")) {
		t.Errorf("Bytes() = %q, want %q", h.Bytes(), "hashed")
	}
}

func TestPasswordHashBytesIsolation(t *testing.T) {
	in := []byte("secret")
	h := mustPasswordHash(t, in)

	in[0] = 'X' // mutate the constructor input
	if !bytes.Equal(h.Bytes(), []byte("secret")) {
		t.Error("constructor did not copy input; external mutation leaked in")
	}

	out := h.Bytes()
	out[0] = 'Y' // mutate the returned slice
	if !bytes.Equal(h.Bytes(), []byte("secret")) {
		t.Error("Bytes() exposed internal slice; mutation leaked out")
	}
}

func TestNewTOTPSecret(t *testing.T) {
	if _, err := domain.NewTOTPSecret(nil); !errors.Is(err, domain.ErrEmptyTOTPSecret) {
		t.Errorf("nil err = %v, want ErrEmptyTOTPSecret", err)
	}
	s := mustTOTPSecret(t, []byte("seed"))
	if s.IsZero() || !bytes.Equal(s.Bytes(), []byte("seed")) {
		t.Errorf("secret not stored correctly")
	}
}

// --- PasswordCredential ----------------------------------------------------

func TestNewPasswordCredential(t *testing.T) {
	uid := mustUserID(t)
	hash := mustPasswordHash(t, []byte("h"))

	t.Run("ok", func(t *testing.T) {
		c, err := domain.NewPasswordCredential(uid, hash)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if c.ID().IsZero() {
			t.Error("id not set")
		}
		if c.UserID() != uid {
			t.Errorf("userID = %v, want %v", c.UserID(), uid)
		}
		if c.Type() != domain.CredentialPassword {
			t.Errorf("type = %v, want password", c.Type())
		}
		if !c.CreatedAt().Equal(c.UpdatedAt()) {
			t.Error("createdAt and updatedAt should match on creation")
		}
	})

	t.Run("zero userID rejected", func(t *testing.T) {
		_, err := domain.NewPasswordCredential(domain.UserID{}, hash)
		if !errors.Is(err, domain.ErrInvalidUserID) {
			t.Errorf("err = %v, want ErrInvalidUserID", err)
		}
	})

	t.Run("empty hash rejected", func(t *testing.T) {
		_, err := domain.NewPasswordCredential(uid, domain.PasswordHash{})
		if !errors.Is(err, domain.ErrEmptyPasswordHash) {
			t.Errorf("err = %v, want ErrEmptyPasswordHash", err)
		}
	})
}

func TestPasswordCredentialRotate(t *testing.T) {
	c, err := domain.NewPasswordCredential(mustUserID(t), mustPasswordHash(t, []byte("old")))
	if err != nil {
		t.Fatal(err)
	}

	if err := c.Rotate(mustPasswordHash(t, []byte("new"))); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if !bytes.Equal(c.Hash().Bytes(), []byte("new")) {
		t.Errorf("hash = %q, want new", c.Hash().Bytes())
	}
	if c.UpdatedAt().Before(c.CreatedAt()) {
		t.Error("updatedAt went backwards after rotate")
	}

	if err := c.Rotate(domain.PasswordHash{}); !errors.Is(err, domain.ErrEmptyPasswordHash) {
		t.Errorf("rotate empty err = %v, want ErrEmptyPasswordHash", err)
	}
}

// --- OAuthCredential -------------------------------------------------------

func TestNewOAuthCredential(t *testing.T) {
	uid := mustUserID(t)

	tests := []struct {
		name     string
		userID   domain.UserID
		provider domain.Provider
		subject  string
		wantErr  error
	}{
		{"ok", uid, domain.ProviderGoogle, "sub-123", nil},
		{"trims subject", uid, domain.ProviderGitHub, "  gh-9  ", nil},
		{"zero userID", domain.UserID{}, domain.ProviderGoogle, "x", domain.ErrInvalidUserID},
		{"bad provider", uid, domain.Provider("aol"), "x", domain.ErrInvalidProvider},
		{"empty subject", uid, domain.ProviderGoogle, "   ", domain.ErrEmptySubject},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, err := domain.NewOAuthCredential(tc.userID, tc.provider, tc.subject)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr != nil {
				return
			}
			if c.Type() != domain.CredentialOAuth {
				t.Errorf("type = %v, want oauth", c.Type())
			}
			if c.Provider() != tc.provider {
				t.Errorf("provider = %v, want %v", c.Provider(), tc.provider)
			}
			if got, want := c.Subject(), "sub-123"; tc.name == "ok" && got != want {
				t.Errorf("subject = %q, want %q", got, want)
			}
			if tc.name == "trims subject" && c.Subject() != "gh-9" {
				t.Errorf("subject = %q, want trimmed gh-9", c.Subject())
			}
		})
	}
}

// --- OTPCredential ---------------------------------------------------------

func TestNewOTPCredential(t *testing.T) {
	uid := mustUserID(t)
	secret := mustTOTPSecret(t, []byte("seed"))

	tests := []struct {
		name       string
		userID     domain.UserID
		secret     domain.TOTPSecret
		digits     int
		wantErr    error
		wantDigits int
	}{
		{"default digits", uid, secret, 0, nil, 6},
		{"explicit 8", uid, secret, 8, nil, 8},
		{"zero userID", domain.UserID{}, secret, 6, domain.ErrInvalidUserID, 0},
		{"empty secret", uid, domain.TOTPSecret{}, 6, domain.ErrEmptyTOTPSecret, 0},
		{"too few digits", uid, secret, 5, domain.ErrInvalidOTPDigits, 0},
		{"too many digits", uid, secret, 9, domain.ErrInvalidOTPDigits, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, err := domain.NewOTPCredential(tc.userID, tc.secret, tc.digits)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr != nil {
				return
			}
			if c.Digits() != tc.wantDigits {
				t.Errorf("digits = %d, want %d", c.Digits(), tc.wantDigits)
			}
			if c.Type() != domain.CredentialOTP {
				t.Errorf("type = %v, want otp", c.Type())
			}
			if c.Confirmed() {
				t.Error("new OTP credential should be unconfirmed")
			}
		})
	}
}

func TestOTPCredentialConfirm(t *testing.T) {
	c, err := domain.NewOTPCredential(mustUserID(t), mustTOTPSecret(t, []byte("seed")), 0)
	if err != nil {
		t.Fatal(err)
	}

	if err := c.Confirm(); err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	if !c.Confirmed() {
		t.Error("not confirmed after Confirm")
	}
	if err := c.Confirm(); !errors.Is(err, domain.ErrOTPAlreadyConfirmed) {
		t.Errorf("second confirm err = %v, want ErrOTPAlreadyConfirmed", err)
	}
}
