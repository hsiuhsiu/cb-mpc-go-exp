package cbmpc

import (
	"errors"
	"testing"
)

func TestVersionReturnsConfiguredValue(t *testing.T) {
	want := Version
	if want == "" {
		t.Fatal("expected default version to be non-empty")
	}
	if got := WrapperVersion(); got != want {
		t.Fatalf("expected wrapper version %q, got %q", want, got)
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
