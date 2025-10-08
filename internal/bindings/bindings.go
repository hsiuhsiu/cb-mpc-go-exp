//go:build cgo && !windows

// Package bindings provides the CGO bridge between Go and the C++ cb-mpc library.
//
// The package is organized as follows:
//   - bindings.go: CGO build configuration (this file)
//   - bindings_types.go: Type conversions (cmemToGoBytes) and common types
//   - bindings_job.go: Transport interface, handle registry, CGO export callbacks, and job lifecycle management
//   - bindings_protocol.go: MPC protocol implementations (AgreeRandom2P, AgreeRandomMP)
//   - bindings_stub.go: Stub implementations for non-CGO builds or Windows
package bindings

/*
#cgo CFLAGS: -I${SRCDIR}/../../cb-mpc/src -I${SRCDIR}/../../cb-mpc/src/cbmpc -Wno-parentheses
#cgo CXXFLAGS: -std=c++17 -I${SRCDIR}/../../cb-mpc/src -I${SRCDIR}/../../cb-mpc/src/cbmpc -Wno-parentheses
#cgo LDFLAGS: -L${SRCDIR}/../../cb-mpc/lib/Release -lcbmpc -lcrypto -ldl

// OpenSSL paths are set via CGO_CFLAGS, CGO_CXXFLAGS, and CGO_LDFLAGS environment variables.
// These are configured by the build scripts based on CBMPC_ENV_FLAVOR (host or docker).
// See scripts/run_with_go.sh for the environment setup.
*/
import "C"
