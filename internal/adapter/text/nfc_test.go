package text_test

import (
	"testing"

	"authentication/internal/adapter/text"
)

func TestNFCComposesEquivalentForms(t *testing.T) {
	n := text.NFC{}
	// U+0065 U+0301 (e + combining acute) and U+00E9 (precomposed é) are
	// canonically equivalent; NFC must collapse them to the same bytes.
	decomposed := "é"
	precomposed := "é"
	if n.Normalize(decomposed) != n.Normalize(precomposed) {
		t.Errorf("NFC did not unify equivalent forms: %q vs %q",
			n.Normalize(decomposed), n.Normalize(precomposed))
	}
	if n.Normalize(precomposed) != precomposed {
		t.Errorf("NFC of already-composed form changed it: %q", n.Normalize(precomposed))
	}
}

func TestNFCLeavesASCIIUnchanged(t *testing.T) {
	n := text.NFC{}
	if got := n.Normalize("Hunter2-Password!"); got != "Hunter2-Password!" {
		t.Errorf("ASCII changed: %q", got)
	}
}
