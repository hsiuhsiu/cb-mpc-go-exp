//go:build cgo && !windows

// Package bindings provides the CGO bridge between Go and the C++ cb-mpc library.
//
// The package is organized as follows:
//   - bindings.go: CGO build configuration (this file)
//   - bindings_types.go: Type conversions, transport interface, and CGO export callbacks
//   - bindings_job.go: Job lifecycle management (NewJob2P, FreeJob2P, NewJobMP, FreeJobMP)
//   - bindings_protocol.go: MPC protocol implementations (AgreeRandom2P, AgreeRandomMP)
//
// The CGO export callbacks (cbmpc_go_send, cbmpc_go_receive, cbmpc_go_receive_all)
// are defined in bindings_types.go and allow the C++ library to call back into Go
// for network operations.
package bindings

/*
#cgo CFLAGS: -I${SRCDIR}/../../cb-mpc/src -I${SRCDIR}/../../cb-mpc/src/cbmpc -I${SRCDIR}/../../build/openssl-host/include -I${SRCDIR}/../../build/openssl-docker/include -Wno-parentheses
#cgo CXXFLAGS: -std=c++17 -I${SRCDIR}/../../cb-mpc/src -I${SRCDIR}/../../cb-mpc/src/cbmpc -I${SRCDIR}/../../build/openssl-host/include -I${SRCDIR}/../../build/openssl-docker/include -Wno-parentheses
#cgo LDFLAGS: -L${SRCDIR}/../../cb-mpc/lib/Release -L${SRCDIR}/../../build/openssl-docker/lib -L${SRCDIR}/../../build/openssl-docker/lib64 -L${SRCDIR}/../../build/openssl-host/lib -L${SRCDIR}/../../build/openssl-host/lib64 -lcbmpc -lcrypto -ldl
*/
import "C"
