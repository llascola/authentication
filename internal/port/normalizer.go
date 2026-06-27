package port

// Normalizer puts a Unicode string into a canonical form before it is hashed or
// compared. Passwords must be NFC-normalized so that two visually identical
// inputs entered with different code-point sequences (composed vs decomposed)
// hash to the same value (ADR 0006).
//
// It is a port, not a domain concern: the dependency-free domain must not import
// a Unicode table library. The real implementation (golang.org/x/text) lives in
// an adapter and is wired at main; keeping the contract here lets the
// application normalize transient plaintext without taking that dependency
// itself.
type Normalizer interface {
	// Normalize returns s in canonical form. It is pure: no I/O, no error.
	Normalize(s string) string
}
