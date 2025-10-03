package cbmpc

import "github.com/coinbase/cb-mpc-go/internal/bindings"

// Library represents an opened handle to the native cb-mpc library. The struct
// keeps enough metadata to gracefully close the handle once real bindings are
// available.
type Library struct {
	cfg    Config
	handle bindings.Handle
	closed bool
}

// Open prepares the native library. Today it only wires the placeholder error
// mapping so that callers can start integrating the control flow.
func Open(cfg Config) (*Library, error) {
	h, err := bindings.Open(cfg.toBindings())
	if err != nil {
		return nil, remapError(err)
	}

	return &Library{cfg: cfg, handle: h}, nil
}

// Close releases the native resources associated with the library handle. The
// method is idempotent, returning ErrLibraryClosed when called twice.
func (l *Library) Close() error {
	if l == nil {
		return nil
	}

	if l.closed {
		return ErrLibraryClosed
	}

	if err := bindings.Close(l.handle); err != nil {
		return remapError(err)
	}

	l.closed = true
	l.handle = 0
	return nil
}
