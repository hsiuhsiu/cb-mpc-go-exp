package cbmpc

import (
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
