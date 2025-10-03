package bindings

import "errors"

// Config captures the parameters required by the native cb-mpc bindings. The
// struct intentionally stays blank for now; real fields arrive once the cgo
// layer is wired up.
type Config struct{}

// Handle is an opaque identifier returned by the native library when it is
// successfully opened.
type Handle uintptr

var (
	// ErrNotBuilt reports that the native bindings were not linked into the
	// current binary. CI and downstream callers can use this to fall back to
	// safer defaults.
	ErrNotBuilt = errors.New("cbmpc/internal/bindings: native bindings not built")

	// ErrCGONotEnabled signals that the package was compiled without cgo and
	// therefore cannot talk to the native library.
	ErrCGONotEnabled = errors.New("cbmpc/internal/bindings: cgo not enabled")
)
