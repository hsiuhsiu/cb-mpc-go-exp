# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

cb-mpc-go is a Go wrapper for the Coinbase MPC (Multi-Party Computation) C++ library. It provides idiomatic Go APIs for secure threshold cryptography protocols including ECDSA, EdDSA, Schnorr signatures, key generation, and more.

The project uses CGO to bridge between Go and the C++ library located in the `cb-mpc` submodule.

## Key Design Decisions

1. **CGO Isolation**: ALL CGO code is in `internal/cgo`. No other package imports "C"
2. **Pure Go Public API**: `pkg/mpc` is 100% Go with zero CGO exposure
3. **Session Abstraction**: Network transport is handled in pure Go, not via C callbacks
4. **Explicit Lifecycle**: Use `Close()` methods, not finalizers
5. **Minimal CGO Crossings**: Batch operations to reduce overhead

## Development Commands

### Building

**Important**: All Go commands must be run through `scripts/go_with_cpp.sh` to set proper CGO environment variables.

**Fast Workflow** (Makefile automatically skips C++ rebuild if already built):
- Run tests: `make test` (~0.5s after first build)
- Build Go code: `make build`
- Run examples: `make examples`

**Full Build** (only needed first time or after C++ changes):
- Build C++ library: `make build-cpp` (checks if rebuild needed)
- Force rebuild C++: `make force-build-cpp`
- Clean everything: `make clean-all`

**How it works**: The Makefile tracks `cb-mpc/lib/Release/libcbmpc.a` and only rebuilds if missing or outdated. This makes iterative development much faster!

### Direct Go Commands

If you need to run Go commands directly:
```bash
bash scripts/go_with_cpp.sh go test ./...
bash scripts/go_with_cpp.sh go build ./...
```

### C++ Library Development

The cb-mpc submodule has its own build system:
- Build: `cd cb-mpc && make build`
- Test: `cd cb-mpc && make test`
- Benchmarks: `cd cb-mpc && make bench`

## Architecture

### Directory Structure

```
.
├── pkg/mpc/                      # Public Go API (pure Go, no CGO)
│   ├── doc.go                    # Package documentation
│   ├── types.go                  # Core types (Curve, Party, Session, KeyShare)
│   ├── errors.go                 # Error definitions
│   ├── ecdsa.go                  # ECDSA protocols (2PC and MPC)
│   ├── session.go                # Session implementation (in-memory testing)
│   └── *_test.go                 # Tests
├── internal/cgo/                 # CGO bindings (private, isolated)
│   ├── binding.go                # CGO configuration and common code
│   ├── doc.go                    # Internal documentation
│   └── *.go                      # Protocol-specific bindings (future)
├── examples/                     # Example programs
│   └── ecdsa2pc/                 # Two-party ECDSA example
├── scripts/                      # Build scripts
│   ├── build_cpp.sh              # Build cb-mpc C++ library
│   └── go_with_cpp.sh            # Wrapper for Go commands with CGO env
├── cb-mpc/                       # Git submodule: Coinbase MPC C++ library
├── Makefile                      # Build automation
├── README.md                     # User documentation
└── CLAUDE.md                     # This file
```

### Three-Layer Architecture

1. **Public API Layer** (`pkg/mpc/`)
   - 100% pure Go code (no `import "C"`)
   - Idiomatic Go interfaces: `Session`, `KeyShare`
   - Standard patterns: `context.Context`, `io.Closer`, `error`
   - Example: `ecdsa.KeyGen(ctx, session)` returns `(KeyShare, error)`
   - Session abstraction handles all networking in Go

2. **CGO Binding Layer** (`internal/cgo/`)
   - ONLY place with `import "C"` in the entire codebase
   - Wraps C++ objects as opaque `uintptr` handles
   - Minimal interface to reduce CGO boundary crossings
   - Converts C error codes to Go errors
   - Memory safety: explicit lifecycle management

3. **C++ Library** (`cb-mpc` submodule)
   - Production MPC protocol implementations
   - Constant-time cryptographic primitives
   - Formal specifications and theory papers in `cb-mpc/docs/`

### Key Design Patterns

#### 1. CGO Isolation
**Rule**: Only `internal/cgo` package imports "C". Period.

Why? Minimizes CGO overhead, simplifies maintenance, enables testing without CGO.

```go
// ✅ CORRECT - pkg/mpc/ecdsa.go
package mpc
// No import "C" here

func (e *ECDSA2PC) KeyGen(ctx context.Context, session Session) (KeyShare, error) {
    // Call internal/cgo functions that handle C++
    return cgo.ECDSA2PCKeyGen(session, e.curve)
}
```

```go
// ❌ WRONG - Don't do this
package mpc
import "C"  // Never import C in public API
```

#### 2. Session Abstraction (No C Callbacks)
**Rule**: Network transport is 100% Go. No C calling into Go.

The `Session` interface handles all message passing in pure Go. This avoids the expensive and complex callback mechanism.

```go
// Pure Go interface
type Session interface {
    Send(toParty int, msg []byte) error
    Receive(fromParty int) ([]byte, error)
}
```

The C++ library is given complete messages to process, then returns results. It never calls back into Go for network operations.

#### 3. Explicit Lifecycle
**Rule**: Use `Close()` methods, not `runtime.SetFinalizer`.

Finalizers are unreliable and add GC pressure. Explicit cleanup is better:

```go
keyShare, err := ecdsa.KeyGen(ctx, session)
defer keyShare.Close()  // Explicit cleanup
```

#### 4. Handle-Based Wrapping
C++ objects are wrapped as opaque `uintptr` handles in `internal/cgo`:

```go
// internal/cgo/handle.go
type Handle uintptr

func (h Handle) isValid() bool { return h != 0 }
```

The actual C++ pointer is never exposed outside `internal/cgo`.

### Supported Protocols

Based on cb-mpc library capabilities:

- **ECDSA-2PC**: Two-party ECDSA key generation and signing
- **ECDSA-MPC**: Multi-party threshold ECDSA
- **EdDSA-MPC**: Multi-party EdDSA (Schnorr signatures)
- **EC-DKG**: Elliptic curve distributed key generation
- **HD Derivation**: MPC-friendly hierarchical deterministic key derivation
- **PVE**: Publicly verifiable encryption (backup/recovery)
- **Zero-Knowledge Proofs**: Various ZK protocols

### CGO Configuration

CGO compiler flags are set in `internal/cgobinding/cmem.go`:
- C++17 standard required
- OpenSSL 3.2.0 dependency (platform-specific paths)
- Links to `libcbmpc.a` (static library)
- Platform-specific optimizations (ARM64 crypto extensions)

Environment variables set by `scripts/go_with_cpp.sh`:
```bash
CGO_CFLAGS="-I${CB_MPC_DIR}/src"
CGO_CXXFLAGS="-I${CB_MPC_DIR}/src"
CGO_LDFLAGS="-L${CB_MPC_DIR}/lib/Release"
```

### Adding New Protocols

To wrap a new C++ protocol:

1. **Design the Go API first** in `pkg/mpc/<protocol>.go`
   - Define pure Go types and interfaces
   - Use `context.Context` for cancellation
   - Return `error` for all fallible operations
   - Use `io.Closer` for resource cleanup

2. **Implement CGO bindings** in `internal/cgo/<protocol>.go`
   - Add `import "C"` and C wrapper functions
   - Convert Go types to C types and vice versa
   - Handle all error checking
   - Manage C++ object lifecycle

3. **Wire them together** in `pkg/mpc/<protocol>.go`
   - Call `internal/cgo` functions
   - Convert handles to Go types
   - Add any Go-side logic (validation, etc.)

Example:
```go
// pkg/mpc/schnorr.go (public API)
type Schnorr2PC struct { curve Curve }

func (s *Schnorr2PC) KeyGen(ctx context.Context, session Session) (KeyShare, error) {
    // Call internal CGO
    handle, err := cgo.SchnorrKeyGen(session, s.curve)
    if err != nil {
        return nil, err
    }
    return &schnorrKeyShare{handle: handle}, nil
}
```

### Testing

- Unit tests should use `transport.MockMessenger` for in-memory networking
- Integration tests may require multiple goroutines simulating different parties
- Always use `bash scripts/go_with_cpp.sh go test` to run tests

### Important Notes

- **Thread Safety**: The C++ library is NOT thread-safe. Protect shared objects with mutexes.
- **Constant Time**: Cryptographic operations aim for constant-time execution (see `cb-mpc/docs/constant-time.pdf`)
- **Compiler**: Upstream Clang 20+ recommended for C++ compilation
- **OpenSSL**: Modified OpenSSL 3.2.0 required (built via `cb-mpc/scripts/openssl/`)

### External Resources

- C++ library docs: `cb-mpc/docs/` (PDF specifications and theory)
- Protocol implementations: `cb-mpc/src/cbmpc/protocol/`
- Example usage: `cb-mpc/demos-go/examples/`
- Coinbase MPC repository: https://github.com/coinbase/cb-mpc
