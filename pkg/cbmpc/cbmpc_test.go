package cbmpc

import "testing"

func TestLibraryVersion(t *testing.T) {
	if got := LibraryVersion(); got == "" {
		t.Fatal("expected placeholder version to be non-empty")
	}
}
