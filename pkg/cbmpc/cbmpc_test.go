package cbmpc

import (
	"errors"
	"testing"
)

func TestVersionFallback(t *testing.T) {
	if got := Version(); got != fallbackVersion {
		t.Fatalf("expected fallback version %q, got %q", fallbackVersion, got)
	}
}

func TestOpenReturnsStubError(t *testing.T) {
	lib, err := Open(Config{})
	if !errors.Is(err, ErrCGONotEnabled) && !errors.Is(err, ErrNotBuilt) {
		t.Fatalf("unexpected error from Open: %v", err)
	}
	if lib != nil {
		t.Fatalf("expected nil library, got %+v", lib)
	}
}
