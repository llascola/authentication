package port

import "context"

// PasswordHasher is the produce side of password crypto: it turns a plaintext
// into an opaque encoded hash for storage. It pairs with Authenticator, which
// is the verify side; together they bracket the bcrypt adapter (T07).
//
// The caller passes a plaintext already NFC-normalized (ADR 0006). The adapter
// owns the full hashing recipe — the prehash that defuses bcrypt's 72-byte
// truncation (base64(sha256(pw))) and the bcrypt cost (ADR 0007). The port says
// nothing about algorithm or cost; callers treat the returned bytes as opaque
// and wrap them with domain.NewPasswordHash for storage.
type PasswordHasher interface {
	// Hash returns the encoded hash for an NFC-normalized plaintext. The result
	// is opaque to the caller. ctx is carried for symmetry and future cost
	// tuning even though bcrypt is CPU-bound. Failure is an infra error; no
	// sentinel is defined.
	Hash(ctx context.Context, plaintext string) ([]byte, error)
}
