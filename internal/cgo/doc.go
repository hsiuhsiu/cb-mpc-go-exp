// Package cgo contains all CGO bindings to the cb-mpc C++ library.
//
// # Design Principles
//
// 1. Isolation: ALL CGO code lives in this package. No other package should
//    import "C". This minimizes CGO overhead and makes the codebase easier to
//    maintain.
//
// 2. Minimal Surface: Expose only what's needed. Don't wrap every C++ function.
//
// 3. Error Handling: Convert all C error codes to Go errors immediately.
//
// 4. Memory Management: Use explicit lifecycle management. C++ objects are
//    wrapped in Go types with Close() methods.
//
// 5. No Callbacks: Avoid Go callbacks from C++. Use message passing instead.
//    The Session abstraction handles all communication in pure Go.
//
// 6. Safety: All exported functions check for nil pointers and invalid state.
//
// # Memory Layout
//
// C++ objects are wrapped as opaque handles (uintptr). The actual C++ pointer
// is never exposed to Go code outside this package.
//
// # Threading
//
// The cb-mpc library is NOT thread-safe. Callers must ensure proper
// synchronization.
package cgo
