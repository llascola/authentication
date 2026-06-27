package screener_test

import (
	"context"
	"testing"

	"authentication/internal/adapter/screener"
)

func TestNoOpAcceptsEverything(t *testing.T) {
	s := screener.NoOp{}
	inputs := map[string]string{
		"normal":   "correct horse battery staple",
		"empty":    "",
		"breached": "password123",
	}
	for name, pw := range inputs {
		if err := s.Screen(context.Background(), pw); err != nil {
			t.Errorf("Screen(%s) = %v, want nil", name, err)
		}
	}
}
