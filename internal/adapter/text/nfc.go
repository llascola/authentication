// Package text provides the Unicode-normalization adapter. It is the single
// place golang.org/x/text enters the build; the application and domain stay
// free of that dependency, depending only on port.Normalizer.
package text

import (
	"golang.org/x/text/unicode/norm"

	"authentication/internal/port"
)

var _ port.Normalizer = NFC{}

// NFC normalizes strings to Unicode Normalization Form C (canonical
// composition), the form ADR 0006 requires for passwords before hashing.
type NFC struct{}

// Normalize returns s in NFC.
func (NFC) Normalize(s string) string { return norm.NFC.String(s) }
