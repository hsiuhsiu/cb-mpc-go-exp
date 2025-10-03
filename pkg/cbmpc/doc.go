// Package cbmpc exposes a future-facing Go API for the Coinbase cb-mpc
// library. The exported types compile today without linking the native
// bindings so that downstream projects can adopt the package without pulling in
// cgo immediately. Once the bindings are implemented the same API will surface
// the real MPC primitives.
package cbmpc
