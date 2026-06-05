package domain_test

import (
	"errors"
	"strings"
	"testing"

	"authentication/internal/domain"
)

// --- NewPasswordPolicy (config validation) ---------------------------------

func TestNewPasswordPolicy(t *testing.T) {
	tests := []struct {
		name    string
		opts    []domain.PolicyOption
		wantErr error
	}{
		{"defaults ok", nil, nil},
		{"custom bounds ok", []domain.PolicyOption{domain.WithMinLength(8), domain.WithMaxLength(64)}, nil},
		{"no max ok", []domain.PolicyOption{domain.WithMaxLength(0)}, nil},
		{"zero min rejected", []domain.PolicyOption{domain.WithMinLength(0)}, domain.ErrInvalidPasswordPolicy},
		{"negative min rejected", []domain.PolicyOption{domain.WithMinLength(-1)}, domain.ErrInvalidPasswordPolicy},
		{"negative max rejected", []domain.PolicyOption{domain.WithMaxLength(-1)}, domain.ErrInvalidPasswordPolicy},
		{"max below min rejected", []domain.PolicyOption{domain.WithMinLength(12), domain.WithMaxLength(8)}, domain.ErrInvalidPasswordPolicy},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := domain.NewPasswordPolicy(tc.opts...)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestPasswordPolicyGetters(t *testing.T) {
	p, err := domain.NewPasswordPolicy(
		domain.WithMinLength(10), domain.WithMaxLength(50),
		domain.RequireUpper(), domain.RequireLower(),
		domain.RequireDigit(), domain.RequireSymbol(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if p.MinLength() != 10 || p.MaxLength() != 50 {
		t.Errorf("bounds = %d/%d, want 10/50", p.MinLength(), p.MaxLength())
	}
	if !p.RequiresUpper() || !p.RequiresLower() || !p.RequiresDigit() || !p.RequiresSymbol() {
		t.Error("class requirements not reflected by getters")
	}
}

func TestDefaultPasswordPolicy(t *testing.T) {
	p := domain.DefaultPasswordPolicy()
	if p.MinLength() != 12 || p.MaxLength() != 72 {
		t.Errorf("default bounds = %d/%d, want 12/72", p.MinLength(), p.MaxLength())
	}
	if !p.RequiresUpper() || !p.RequiresLower() || !p.RequiresDigit() {
		t.Error("default should require upper/lower/digit")
	}
	if p.RequiresSymbol() {
		t.Error("default should not require symbol")
	}
}

// --- Validate (single rules) -----------------------------------------------

func TestPasswordPolicyValidate(t *testing.T) {
	// strict policy with every rule on, short bounds for easy fixtures.
	policy, err := domain.NewPasswordPolicy(
		domain.WithMinLength(8), domain.WithMaxLength(16),
		domain.RequireUpper(), domain.RequireLower(),
		domain.RequireDigit(), domain.RequireSymbol(),
	)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		password string
		wantErrs []error // empty = expect pass
	}{
		{"valid", "Abcdef1!", nil},
		{"too short", "Ab1!", []error{domain.ErrPasswordTooShort}},
		{"too long", "Abcdef1!" + strings.Repeat("x", 16), []error{domain.ErrPasswordTooLong}},
		{"no upper", "abcdef1!", []error{domain.ErrPasswordNoUpper}},
		{"no lower", "ABCDEF1!", []error{domain.ErrPasswordNoLower}},
		{"no digit", "Abcdefg!", []error{domain.ErrPasswordNoDigit}},
		{"no symbol", "Abcdefg1", []error{domain.ErrPasswordNoSymbol}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := policy.Validate(tc.password)
			if len(tc.wantErrs) == 0 {
				if err != nil {
					t.Fatalf("Validate(%q) = %v, want nil", tc.password, err)
				}
				return
			}
			for _, want := range tc.wantErrs {
				if !errors.Is(err, want) {
					t.Errorf("Validate(%q) = %v, want errors.Is %v", tc.password, err, want)
				}
			}
		})
	}
}

// --- Validate (aggregation) ------------------------------------------------

func TestPasswordPolicyAggregatesViolations(t *testing.T) {
	policy, err := domain.NewPasswordPolicy(
		domain.WithMinLength(8),
		domain.RequireUpper(), domain.RequireLower(),
		domain.RequireDigit(), domain.RequireSymbol(),
	)
	if err != nil {
		t.Fatal(err)
	}

	// "ab" trips: too short, no upper, no digit, no symbol (lower is satisfied).
	err = policy.Validate("ab")
	want := []error{
		domain.ErrPasswordTooShort,
		domain.ErrPasswordNoUpper,
		domain.ErrPasswordNoDigit,
		domain.ErrPasswordNoSymbol,
	}
	for _, w := range want {
		if !errors.Is(err, w) {
			t.Errorf("aggregated err missing %v; got %v", w, err)
		}
	}
	if errors.Is(err, domain.ErrPasswordNoLower) {
		t.Error("should not report missing lower for 'ab'")
	}
}

// --- Validate (unicode) ----------------------------------------------------

func TestPasswordPolicyValidateUnicode(t *testing.T) {
	t.Run("length counts runes not bytes", func(t *testing.T) {
		// "résumé!2A" — 9 runes; é is 2 bytes each, so byte len would be 11.
		policy, err := domain.NewPasswordPolicy(
			domain.WithMinLength(9),
			domain.RequireUpper(), domain.RequireLower(),
			domain.RequireDigit(), domain.RequireSymbol(),
		)
		if err != nil {
			t.Fatal(err)
		}
		if err := policy.Validate("résumé!2A"); err != nil {
			t.Errorf("rune-length password rejected: %v", err)
		}
	})

	t.Run("symbol class detects unicode symbol", func(t *testing.T) {
		policy, err := domain.NewPasswordPolicy(domain.WithMinLength(4), domain.RequireSymbol())
		if err != nil {
			t.Fatal(err)
		}
		// '€' is a unicode symbol (Sc); should satisfy RequireSymbol.
		if err := policy.Validate("ab€c"); err != nil {
			t.Errorf("unicode symbol not accepted: %v", err)
		}
	})
}
