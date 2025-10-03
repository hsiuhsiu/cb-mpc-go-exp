package cbmpc

import "github.com/coinbase/cb-mpc-go/internal/bindings"

// Config expresses the knobs required to spin up the native cb-mpc library.
// The fields act as placeholders until the real binding parameters are known;
// callers can start threading the object through their wiring without needing
// cgo today.
type Config struct {
	// HomeDir records where temporary build artifacts or configuration files
	// should live. Leaving it empty lets the library pick sensible defaults.
	HomeDir string

	// EnableZeroization toggles best-effort zeroization of sensitive buffers on
	// shutdown. It is a no-op until the native bindings are available.
	EnableZeroization bool
}

func (c Config) toBindings() bindings.Config {
	return bindings.Config{}
}
