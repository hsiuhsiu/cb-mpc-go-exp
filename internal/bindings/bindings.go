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
#cgo CFLAGS: -I${SRCDIR}/../../cb-mpc/src -I${SRCDIR}/../../cb-mpc/src/cbmpc -I${SRCDIR}/../../build/openssl-host/include -I${SRCDIR}/../../build/openssl-docker/include -Wno-parentheses
#cgo CXXFLAGS: -std=c++17 -I${SRCDIR}/../../cb-mpc/src -I${SRCDIR}/../../cb-mpc/src/cbmpc -I${SRCDIR}/../../build/openssl-host/include -I${SRCDIR}/../../build/openssl-docker/include -Wno-parentheses
#cgo LDFLAGS: -L${SRCDIR}/../../cb-mpc/lib/Release -L${SRCDIR}/../../build/openssl-docker/lib -L${SRCDIR}/../../build/openssl-docker/lib64 -L${SRCDIR}/../../build/openssl-host/lib -L${SRCDIR}/../../build/openssl-host/lib64 -lcbmpc -lcrypto -ldl
*/
import "C"
