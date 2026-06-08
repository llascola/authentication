package domain

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
)

// RecoveryCodeSet errors.
var (
	ErrInvalidRecoveryCodeSetID = errors.New("domain: invalid recovery code set id")
	ErrNoRecoveryCodes          = errors.New("domain: recovery code set must have at least one code")
	ErrTooManyRecoveryCodes     = errors.New("domain: too many recovery codes")
	ErrDuplicateRecoveryCode    = errors.New("domain: duplicate recovery code")
	ErrRecoveryCodeInvalid      = errors.New("domain: invalid or already-used recovery code")
)

// maxRecoveryCodes caps a set; 10 is the common convention, so 20 leaves room
// while still bounding the slice.
const maxRecoveryCodes = 20

// ---------------------------------------------------------------------------
// RecoveryCodeSetID
// ---------------------------------------------------------------------------

// RecoveryCodeSetID is the opaque identity of a generated set of backup codes.
type RecoveryCodeSetID uuid.UUID

func NewRecoveryCodeSetID() RecoveryCodeSetID { return RecoveryCodeSetID(uuid.New()) }

func ParseRecoveryCodeSetID(s string) (RecoveryCodeSetID, error) {
	id, err := uuid.Parse(strings.TrimSpace(s))
	if err != nil {
		return RecoveryCodeSetID{}, fmt.Errorf("%w: %q", ErrInvalidRecoveryCodeSetID, s)
	}
	return RecoveryCodeSetID(id), nil
}

func (id RecoveryCodeSetID) String() string { return uuid.UUID(id).String() }
func (id RecoveryCodeSetID) IsZero() bool   { return uuid.UUID(id) == uuid.Nil }

// ---------------------------------------------------------------------------
// RecoveryCode (entity, internal to the set)
// ---------------------------------------------------------------------------

// RecoveryCode is a single single-use backup code, identified within its set by
// its hash. Only the hash is stored (raw codes are shown once at generation and
// never persisted); usedAt records single-use consumption.
type RecoveryCode struct {
	hash   TokenHash
	usedAt *time.Time
}

// ReconstituteRecoveryCode rebuilds a code from persisted state. Repository only.
func ReconstituteRecoveryCode(hash TokenHash, usedAt *time.Time) RecoveryCode {
	return RecoveryCode{hash: hash, usedAt: clonePtr(usedAt)}
}

func (c RecoveryCode) Hash() TokenHash { return c.hash }
func (c RecoveryCode) IsUsed() bool    { return c.usedAt != nil }

// UsedAt returns the consumption time and whether the code has been used.
func (c RecoveryCode) UsedAt() (time.Time, bool) {
	if c.usedAt == nil {
		return time.Time{}, false
	}
	return *c.usedAt, true
}

// ---------------------------------------------------------------------------
// RecoveryCodeSet (aggregate root)
// ---------------------------------------------------------------------------

// RecoveryCodeSet is the MFA backup set: a batch of single-use codes that let a
// user regain access when their primary second factor is lost. It references its
// owning User by ID. Regenerating codes is modelled as a brand-new set (the repo
// replaces the old one), so there is no in-place regenerate.
type RecoveryCodeSet struct {
	id        RecoveryCodeSetID
	userID    UserID
	codes     []RecoveryCode
	createdAt time.Time
}

// NewRecoveryCodeSet builds a set from already-hashed codes. Code generation and
// hashing are infrastructure crypto (CSPRNG); the domain receives only hashes,
// shown once to the user as raw codes and never persisted in the clear. It
// rejects an empty set, an oversized set, empty hashes, and duplicates.
func NewRecoveryCodeSet(now time.Time, userID UserID, hashes []TokenHash) (*RecoveryCodeSet, error) {
	if userID.IsZero() {
		return nil, ErrInvalidUserID
	}
	if len(hashes) == 0 {
		return nil, ErrNoRecoveryCodes
	}
	if len(hashes) > maxRecoveryCodes {
		return nil, fmt.Errorf("%w: %d > %d", ErrTooManyRecoveryCodes, len(hashes), maxRecoveryCodes)
	}

	codes := make([]RecoveryCode, 0, len(hashes))
	for _, h := range hashes {
		if h.IsZero() {
			return nil, ErrEmptyTokenHash
		}
		for _, existing := range codes {
			if bytes.Equal(existing.hash.Bytes(), h.Bytes()) {
				return nil, ErrDuplicateRecoveryCode
			}
		}
		codes = append(codes, RecoveryCode{hash: h})
	}

	return &RecoveryCodeSet{
		id:        NewRecoveryCodeSetID(),
		userID:    userID,
		codes:     codes,
		createdAt: now,
	}, nil
}

// ReconstituteRecoveryCodeSet rebuilds a set from persisted state without
// invariants. Repository/persistence layer only.
func ReconstituteRecoveryCodeSet(
	id RecoveryCodeSetID,
	userID UserID,
	codes []RecoveryCode,
	createdAt time.Time,
) *RecoveryCodeSet {
	return &RecoveryCodeSet{
		id:        id,
		userID:    userID,
		codes:     slices.Clone(codes),
		createdAt: createdAt,
	}
}

// --- getters ---------------------------------------------------------------

func (s *RecoveryCodeSet) ID() RecoveryCodeSetID { return s.id }
func (s *RecoveryCodeSet) UserID() UserID        { return s.userID }
func (s *RecoveryCodeSet) CreatedAt() time.Time  { return s.createdAt }

// Codes returns a copy of the codes; the internal slice is not exposed.
func (s *RecoveryCodeSet) Codes() []RecoveryCode { return slices.Clone(s.codes) }

// --- queries ---------------------------------------------------------------

// Remaining reports how many codes are still unused.
func (s *RecoveryCodeSet) Remaining() int {
	n := 0
	for _, c := range s.codes {
		if !c.IsUsed() {
			n++
		}
	}
	return n
}

// IsExhausted reports whether every code has been consumed.
func (s *RecoveryCodeSet) IsExhausted() bool { return s.Remaining() == 0 }

// --- behaviour -------------------------------------------------------------

// Consume marks the unused code matching presented as used. It returns
// ErrRecoveryCodeInvalid when no unused code matches (unknown or already spent),
// without disclosing which. The caller compares the user's raw code by hashing
// it the same way the stored hashes were produced (infra), then passes the hash.
func (s *RecoveryCodeSet) Consume(now time.Time, presented TokenHash) error {
	if presented.IsZero() {
		return ErrRecoveryCodeInvalid
	}
	// Scan every unused code with no early exit: returning on first match would
	// leak via timing which code matched and that a match exists. Constant-time
	// hash compare (TokenHash.Equal) closes the prefix leak.
	match := -1
	for i := range s.codes {
		if s.codes[i].IsUsed() {
			continue
		}
		if s.codes[i].hash.Equal(presented) {
			match = i
		}
	}
	if match < 0 {
		return ErrRecoveryCodeInvalid
	}
	used := now
	s.codes[match].usedAt = &used
	return nil
}
