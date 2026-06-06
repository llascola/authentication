package domain_test

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"authentication/internal/domain"
)

// Compile-time proof that every concrete credential satisfies the sealed
// Credential interface. If a type stops implementing it, the package fails to
// build — a cheaper signal than any runtime test.
var (
	_ domain.Credential = (*domain.PasswordCredential)(nil)
	_ domain.Credential = (*domain.OAuthCredential)(nil)
	_ domain.Credential = (*domain.OTPCredential)(nil)
	_ domain.Credential = (*domain.WebAuthnCredential)(nil)
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
		domain.CredentialPassword, domain.CredentialOAuth, domain.CredentialOTP, domain.CredentialWebAuthn,
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

func TestReconstitutePasswordCredential(t *testing.T) {
	id := domain.NewCredentialID()
	uid := mustUserID(t)
	hash := mustPasswordHash(t, []byte("stored"))
	created := time.Now().UTC().Add(-2 * time.Hour)
	updated := created.Add(time.Hour)

	c := domain.ReconstitutePasswordCredential(id, uid, hash, created, updated)
	if c.ID() != id {
		t.Errorf("id = %v, want %v", c.ID(), id)
	}
	if c.UserID() != uid {
		t.Errorf("userID = %v, want %v", c.UserID(), uid)
	}
	if !bytes.Equal(c.Hash().Bytes(), []byte("stored")) {
		t.Errorf("hash = %q, want stored", c.Hash().Bytes())
	}
	if !c.CreatedAt().Equal(created) || !c.UpdatedAt().Equal(updated) {
		t.Errorf("timestamps = (%v, %v), want (%v, %v)", c.CreatedAt(), c.UpdatedAt(), created, updated)
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

func TestReconstituteOAuthCredential(t *testing.T) {
	id := domain.NewCredentialID()
	uid := mustUserID(t)
	created := time.Now().UTC().Add(-time.Hour)

	c := domain.ReconstituteOAuthCredential(id, uid, domain.ProviderGitHub, "gh-42", created)
	if c.ID() != id {
		t.Errorf("id = %v, want %v", c.ID(), id)
	}
	if c.UserID() != uid {
		t.Errorf("userID = %v, want %v", c.UserID(), uid)
	}
	if c.Provider() != domain.ProviderGitHub {
		t.Errorf("provider = %v, want github", c.Provider())
	}
	if c.Subject() != "gh-42" {
		t.Errorf("subject = %q, want gh-42", c.Subject())
	}
	if !c.CreatedAt().Equal(created) {
		t.Errorf("createdAt = %v, want %v", c.CreatedAt(), created)
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

	if !c.CreatedAt().Equal(c.UpdatedAt()) {
		t.Error("createdAt and updatedAt should match on creation")
	}

	if err := c.Confirm(); err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	if !c.Confirmed() {
		t.Error("not confirmed after Confirm")
	}
	if c.UpdatedAt().Before(c.CreatedAt()) {
		t.Error("updatedAt went backwards after confirm")
	}
	if err := c.Confirm(); !errors.Is(err, domain.ErrOTPAlreadyConfirmed) {
		t.Errorf("second confirm err = %v, want ErrOTPAlreadyConfirmed", err)
	}
}

func TestReconstituteOTPCredential(t *testing.T) {
	id := domain.NewCredentialID()
	uid := mustUserID(t)
	secret := mustTOTPSecret(t, []byte("seed"))
	created := time.Now().UTC().Add(-3 * time.Hour)
	updated := created.Add(time.Hour)

	c := domain.ReconstituteOTPCredential(id, uid, secret, 8, true, created, updated)
	if c.ID() != id {
		t.Errorf("id = %v, want %v", c.ID(), id)
	}
	if c.UserID() != uid {
		t.Errorf("userID = %v, want %v", c.UserID(), uid)
	}
	if c.Digits() != 8 {
		t.Errorf("digits = %d, want 8", c.Digits())
	}
	if !c.Confirmed() {
		t.Error("confirmed not preserved on reconstitute")
	}
	if !c.CreatedAt().Equal(created) || !c.UpdatedAt().Equal(updated) {
		t.Errorf("timestamps = (%v, %v), want (%v, %v)", c.CreatedAt(), c.UpdatedAt(), created, updated)
	}
}

// --- WebAuthn value objects ------------------------------------------------

func mustWebAuthnID(t *testing.T, b []byte) domain.WebAuthnID {
	t.Helper()
	w, err := domain.NewWebAuthnID(b)
	if err != nil {
		t.Fatalf("NewWebAuthnID: unexpected error: %v", err)
	}
	return w
}

func mustPublicKey(t *testing.T, b []byte) domain.PublicKey {
	t.Helper()
	k, err := domain.NewPublicKey(b)
	if err != nil {
		t.Fatalf("NewPublicKey: unexpected error: %v", err)
	}
	return k
}

func TestNewWebAuthnID(t *testing.T) {
	if _, err := domain.NewWebAuthnID(nil); !errors.Is(err, domain.ErrEmptyWebAuthnID) {
		t.Errorf("nil err = %v, want ErrEmptyWebAuthnID", err)
	}
	w := mustWebAuthnID(t, []byte("cred-handle"))
	if w.IsZero() || !bytes.Equal(w.Bytes(), []byte("cred-handle")) {
		t.Error("webauthn id not stored correctly")
	}
}

func TestNewPublicKey(t *testing.T) {
	if _, err := domain.NewPublicKey([]byte{}); !errors.Is(err, domain.ErrEmptyPublicKey) {
		t.Errorf("empty err = %v, want ErrEmptyPublicKey", err)
	}
	k := mustPublicKey(t, []byte("cose-key"))
	if k.IsZero() || !bytes.Equal(k.Bytes(), []byte("cose-key")) {
		t.Error("public key not stored correctly")
	}
}

func TestWebAuthnBytesIsolation(t *testing.T) {
	in := []byte("k")
	w := mustWebAuthnID(t, in)
	k := mustPublicKey(t, in)

	in[0] = 'X'
	if !bytes.Equal(w.Bytes(), []byte("k")) || !bytes.Equal(k.Bytes(), []byte("k")) {
		t.Error("constructor did not copy input")
	}
	out := w.Bytes()
	out[0] = 'Y'
	if !bytes.Equal(w.Bytes(), []byte("k")) {
		t.Error("Bytes() exposed internal slice")
	}
}

// --- WebAuthnCredential ----------------------------------------------------

func TestNewWebAuthnCredential(t *testing.T) {
	uid := mustUserID(t)

	t.Run("ok", func(t *testing.T) {
		c, err := domain.NewWebAuthnCredential(uid, mustWebAuthnID(t, []byte("h")), mustPublicKey(t, []byte("pk")), 5)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if c.ID().IsZero() {
			t.Error("id not set")
		}
		if c.Type() != domain.CredentialWebAuthn {
			t.Errorf("type = %v, want webauthn", c.Type())
		}
		if c.SignCount() != 5 {
			t.Errorf("signCount = %d, want 5", c.SignCount())
		}
		if !c.CreatedAt().Equal(c.UpdatedAt()) {
			t.Error("createdAt and updatedAt should match on creation")
		}
		// satisfies the sealed Credential interface
		var _ domain.Credential = c
	})

	tests := []struct {
		name       string
		userID     domain.UserID
		webAuthnID domain.WebAuthnID
		publicKey  domain.PublicKey
		wantErr    error
	}{
		{"zero userID", domain.UserID{}, mustWebAuthnID(t, []byte("h")), mustPublicKey(t, []byte("pk")), domain.ErrInvalidUserID},
		{"empty webauthn id", uid, domain.WebAuthnID{}, mustPublicKey(t, []byte("pk")), domain.ErrEmptyWebAuthnID},
		{"empty public key", uid, mustWebAuthnID(t, []byte("h")), domain.PublicKey{}, domain.ErrEmptyPublicKey},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := domain.NewWebAuthnCredential(tc.userID, tc.webAuthnID, tc.publicKey, 0)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestWebAuthnVerifyCounter(t *testing.T) {
	newCred := func(t *testing.T, start uint32) *domain.WebAuthnCredential {
		t.Helper()
		c, err := domain.NewWebAuthnCredential(mustUserID(t), mustWebAuthnID(t, []byte("h")), mustPublicKey(t, []byte("pk")), start)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	t.Run("advance accepted and recorded", func(t *testing.T) {
		c := newCred(t, 5)
		if err := c.VerifyCounter(6); err != nil {
			t.Fatalf("VerifyCounter: %v", err)
		}
		if c.SignCount() != 6 {
			t.Errorf("signCount = %d, want 6", c.SignCount())
		}
	})

	t.Run("zero on both sides accepted (counter-less)", func(t *testing.T) {
		c := newCred(t, 0)
		if err := c.VerifyCounter(0); err != nil {
			t.Errorf("0/0 err = %v, want nil", err)
		}
		if c.SignCount() != 0 {
			t.Errorf("signCount = %d, want 0", c.SignCount())
		}
	})

	t.Run("equal counter rejected as clone", func(t *testing.T) {
		c := newCred(t, 7)
		if err := c.VerifyCounter(7); !errors.Is(err, domain.ErrAuthenticatorCloned) {
			t.Errorf("err = %v, want ErrAuthenticatorCloned", err)
		}
		if c.SignCount() != 7 {
			t.Error("rejected counter must not mutate signCount")
		}
	})

	t.Run("regressed counter rejected as clone", func(t *testing.T) {
		c := newCred(t, 10)
		if err := c.VerifyCounter(3); !errors.Is(err, domain.ErrAuthenticatorCloned) {
			t.Errorf("err = %v, want ErrAuthenticatorCloned", err)
		}
	})

	t.Run("zero after non-zero rejected as clone", func(t *testing.T) {
		c := newCred(t, 4)
		if err := c.VerifyCounter(0); !errors.Is(err, domain.ErrAuthenticatorCloned) {
			t.Errorf("err = %v, want ErrAuthenticatorCloned", err)
		}
	})
}

func TestReconstituteWebAuthnCredential(t *testing.T) {
	id := domain.NewCredentialID()
	uid := mustUserID(t)
	waID := mustWebAuthnID(t, []byte("handle"))
	pk := mustPublicKey(t, []byte("cose"))
	created := time.Now().UTC().Add(-4 * time.Hour)
	updated := created.Add(2 * time.Hour)

	c := domain.ReconstituteWebAuthnCredential(id, uid, waID, pk, 42, created, updated)
	if c.ID() != id {
		t.Errorf("id = %v, want %v", c.ID(), id)
	}
	if c.UserID() != uid {
		t.Errorf("userID = %v, want %v", c.UserID(), uid)
	}
	if !bytes.Equal(c.WebAuthnID().Bytes(), []byte("handle")) {
		t.Errorf("webAuthnID = %q, want handle", c.WebAuthnID().Bytes())
	}
	if !bytes.Equal(c.PublicKey().Bytes(), []byte("cose")) {
		t.Errorf("publicKey = %q, want cose", c.PublicKey().Bytes())
	}
	if c.SignCount() != 42 {
		t.Errorf("signCount = %d, want 42", c.SignCount())
	}
	if !c.CreatedAt().Equal(created) || !c.UpdatedAt().Equal(updated) {
		t.Errorf("timestamps = (%v, %v), want (%v, %v)", c.CreatedAt(), c.UpdatedAt(), created, updated)
	}

	// reconstituted signCount feeds clone detection: an advance past it works,
	// a repeat is rejected.
	if err := c.VerifyCounter(43); err != nil {
		t.Errorf("advance past reconstituted count: %v", err)
	}
	if err := c.VerifyCounter(42); !errors.Is(err, domain.ErrAuthenticatorCloned) {
		t.Errorf("err = %v, want ErrAuthenticatorCloned", err)
	}
}
