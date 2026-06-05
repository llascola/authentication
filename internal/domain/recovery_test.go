package domain_test

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"authentication/internal/domain"
)

// --- helpers ---------------------------------------------------------------

// hashes builds n distinct token hashes for fixtures.
func hashes(t *testing.T, n int) []domain.TokenHash {
	t.Helper()
	out := make([]domain.TokenHash, n)
	for i := range out {
		out[i] = mustTokenHash(t, fmt.Appendf(nil, "code-%d", i))
	}
	return out
}

func mustRecoveryCodeSet(t *testing.T, n int) *domain.RecoveryCodeSet {
	t.Helper()
	s, err := domain.NewRecoveryCodeSet(mustUserID(t), hashes(t, n))
	if err != nil {
		t.Fatalf("NewRecoveryCodeSet: unexpected error: %v", err)
	}
	return s
}

// --- RecoveryCodeSetID -----------------------------------------------------

func TestRecoveryCodeSetID(t *testing.T) {
	id := domain.NewRecoveryCodeSetID()
	if id.IsZero() {
		t.Fatal("NewRecoveryCodeSetID returned zero id")
	}
	parsed, err := domain.ParseRecoveryCodeSetID(id.String())
	if err != nil {
		t.Fatalf("ParseRecoveryCodeSetID round-trip: %v", err)
	}
	if parsed != id {
		t.Errorf("round-trip = %v, want %v", parsed, id)
	}
	if _, err := domain.ParseRecoveryCodeSetID("nope"); !errors.Is(err, domain.ErrInvalidRecoveryCodeSetID) {
		t.Errorf("err = %v, want ErrInvalidRecoveryCodeSetID", err)
	}
}

// --- NewRecoveryCodeSet ----------------------------------------------------

func TestNewRecoveryCodeSet(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		s := mustRecoveryCodeSet(t, 10)
		if s.ID().IsZero() {
			t.Error("id not set")
		}
		if s.Remaining() != 10 {
			t.Errorf("remaining = %d, want 10", s.Remaining())
		}
		if s.IsExhausted() {
			t.Error("fresh set should not be exhausted")
		}
		if len(s.Codes()) != 10 {
			t.Errorf("codes = %d, want 10", len(s.Codes()))
		}
	})

	uid := mustUserID(t)

	t.Run("zero userID", func(t *testing.T) {
		if _, err := domain.NewRecoveryCodeSet(domain.UserID{}, hashes(t, 3)); !errors.Is(err, domain.ErrInvalidUserID) {
			t.Errorf("err = %v, want ErrInvalidUserID", err)
		}
	})

	t.Run("empty set", func(t *testing.T) {
		if _, err := domain.NewRecoveryCodeSet(uid, nil); !errors.Is(err, domain.ErrNoRecoveryCodes) {
			t.Errorf("err = %v, want ErrNoRecoveryCodes", err)
		}
	})

	t.Run("too many", func(t *testing.T) {
		if _, err := domain.NewRecoveryCodeSet(uid, hashes(t, 21)); !errors.Is(err, domain.ErrTooManyRecoveryCodes) {
			t.Errorf("err = %v, want ErrTooManyRecoveryCodes", err)
		}
	})

	t.Run("empty hash rejected", func(t *testing.T) {
		hs := hashes(t, 3)
		hs[1] = domain.TokenHash{}
		if _, err := domain.NewRecoveryCodeSet(uid, hs); !errors.Is(err, domain.ErrEmptyTokenHash) {
			t.Errorf("err = %v, want ErrEmptyTokenHash", err)
		}
	})

	t.Run("duplicate rejected", func(t *testing.T) {
		dup := mustTokenHash(t, []byte("same"))
		if _, err := domain.NewRecoveryCodeSet(uid, []domain.TokenHash{dup, dup}); !errors.Is(err, domain.ErrDuplicateRecoveryCode) {
			t.Errorf("err = %v, want ErrDuplicateRecoveryCode", err)
		}
	})
}

// --- Consume ---------------------------------------------------------------

func TestRecoveryCodeSetConsume(t *testing.T) {
	t.Run("valid code consumed once", func(t *testing.T) {
		hs := hashes(t, 3)
		s, err := domain.NewRecoveryCodeSet(mustUserID(t), hs)
		if err != nil {
			t.Fatal(err)
		}

		if err := s.Consume(hs[1]); err != nil {
			t.Fatalf("Consume: %v", err)
		}
		if s.Remaining() != 2 {
			t.Errorf("remaining = %d, want 2", s.Remaining())
		}
		// second use of the same code fails (single-use).
		if err := s.Consume(hs[1]); !errors.Is(err, domain.ErrRecoveryCodeInvalid) {
			t.Errorf("reuse err = %v, want ErrRecoveryCodeInvalid", err)
		}
	})

	t.Run("unknown code rejected", func(t *testing.T) {
		s := mustRecoveryCodeSet(t, 3)
		other := mustTokenHash(t, []byte("not-in-set"))
		if err := s.Consume(other); !errors.Is(err, domain.ErrRecoveryCodeInvalid) {
			t.Errorf("err = %v, want ErrRecoveryCodeInvalid", err)
		}
		if s.Remaining() != 3 {
			t.Error("failed consume must not change remaining")
		}
	})

	t.Run("zero hash rejected", func(t *testing.T) {
		s := mustRecoveryCodeSet(t, 3)
		if err := s.Consume(domain.TokenHash{}); !errors.Is(err, domain.ErrRecoveryCodeInvalid) {
			t.Errorf("err = %v, want ErrRecoveryCodeInvalid", err)
		}
	})

	t.Run("consuming all exhausts the set", func(t *testing.T) {
		hs := hashes(t, 3)
		s, err := domain.NewRecoveryCodeSet(mustUserID(t), hs)
		if err != nil {
			t.Fatal(err)
		}
		for _, h := range hs {
			if err := s.Consume(h); err != nil {
				t.Fatalf("Consume: %v", err)
			}
		}
		if !s.IsExhausted() {
			t.Error("set should be exhausted")
		}
		if s.Remaining() != 0 {
			t.Errorf("remaining = %d, want 0", s.Remaining())
		}
	})
}

// --- RecoveryCode + Reconstitute -------------------------------------------

func TestReconstituteRecoveryCodeSet(t *testing.T) {
	id := domain.NewRecoveryCodeSetID()
	uid := domain.NewUserID()
	used := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	codes := []domain.RecoveryCode{
		domain.ReconstituteRecoveryCode(mustTokenHash(t, []byte("a")), nil),
		domain.ReconstituteRecoveryCode(mustTokenHash(t, []byte("b")), &used),
	}
	s := domain.ReconstituteRecoveryCodeSet(id, uid, codes, used)

	if s.ID() != id || s.UserID() != uid {
		t.Error("reconstitute did not preserve core fields")
	}
	if s.Remaining() != 1 {
		t.Errorf("remaining = %d, want 1 (one used)", s.Remaining())
	}

	got := s.Codes()
	if len(got) != 2 {
		t.Fatalf("codes = %d, want 2", len(got))
	}
	if got[0].IsUsed() {
		t.Error("first code should be unused")
	}
	if ts, ok := got[1].UsedAt(); !ok || !ts.Equal(used) {
		t.Error("second code usedAt not preserved")
	}
}

func TestRecoveryCodesGetterIsCopy(t *testing.T) {
	hs := hashes(t, 2)
	s, err := domain.NewRecoveryCodeSet(mustUserID(t), hs)
	if err != nil {
		t.Fatal(err)
	}
	// mutating the returned slice must not affect the aggregate.
	got := s.Codes()
	got = got[:0]
	_ = got
	if s.Remaining() != 2 {
		t.Error("mutating returned slice leaked into aggregate")
	}
}
