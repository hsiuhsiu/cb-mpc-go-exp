package cbmpc

import "github.com/coinbase/cb-mpc-go/internal/bindings"

const fallbackVersion = "unbuilt"

// Version reports the semantic version of the linked cb-mpc native library.
// Until the bindings are available the function returns a placeholder value so
// callers can surface diagnostics without crashing.
func Version() string {
	if v := bindings.Version(); v != "" {
		return v
	}
	return fallbackVersion
}
