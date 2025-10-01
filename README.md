# cb-mpc-go

test

Go bindings for [Coinbase's MPC library](https://github.com/coinbase/cb-mpc) - enabling secure multi-party computation for threshold cryptography.

**🎯 Production-grade MPC protocols** with formal security proofs, constant-time implementations, and comprehensive testing including malicious party scenarios.

## Features

- **🔐 Threshold Signatures**: ECDSA, EdDSA, and Schnorr in both 2PC and multi-party variants
- **🔑 Key Management**: Distributed key generation, HD derivation, and proactive refresh
- **🛡️ Backup & Recovery**: Publicly verifiable encryption with access control
- **🔍 Zero-Knowledge**: Comprehensive ZK proof systems for privacy-preserving protocols
- **⚡ High Performance**: Optimized C++ cryptography with minimal Go/CGO overhead
- **🛠️ Pure Go API**: Idiomatic Go interfaces with complete CGO isolation
- **🔒 Production Ready**: Formal specifications, constant-time operations, and comprehensive testing

## Installation

```bash
# Clone the repository
git clone https://github.com/coinbase/cb-mpc-go.git
cd cb-mpc-go

# Initialize submodules
make deps

# Build C++ library and Go wrapper
make build
```

### Prerequisites

- **Go** 1.21 or later
- **C++17** compiler (Clang 20+ recommended)
- **CMake** 3.15+
- **OpenSSL** 3.2.0 (will be built automatically on macOS)

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "sync"
    "github.com/coinbase/cb-mpc-go/pkg/mpc"
)

func main() {
    // Create a mock network with 2 parties (for testing)
    sessions := mpc.NewMockNetwork(2)

    ctx := context.Background()
    bitLen := 256

    // Run the protocol in parallel for both parties
    var wg sync.WaitGroup
    results := make([][]byte, 2)

    for i := 0; i < 2; i++ {
        wg.Add(1)
        go func(partyIndex int) {
            defer wg.Done()
            // Both parties execute the protocol
            result, _ := mpc.AgreeRandom2PC(ctx, sessions[partyIndex], bitLen)
            results[partyIndex] = result
        }(i)
    }

    wg.Wait()

    // Both parties agreed on the same random value
    fmt.Printf("Party 0: %x\n", results[0][:8])
    fmt.Printf("Party 1: %x\n", results[1][:8])
    // Output: Party 0 and Party 1 have identical random values!
}
```

## Examples

### Basic In-Memory Example

See [examples/agree_random/](examples/agree_random/) for a simple demonstration using mock networking.

### Production mTLS Examples

#### Agree Random with mTLS
See [examples/agree_random_mtls/](examples/agree_random_mtls/) for a **production-ready example** with:
- ✅ Mutual TLS authentication
- ✅ Multi-terminal execution (simulates distributed deployment)
- ✅ Certificate-based party authentication
- ✅ Easy adaptation to internet deployment
- ✅ Configuration file support

```bash
cd examples/agree_random_mtls
./setup.sh    # Generate certificates
./run.sh      # Run all parties (or run manually in separate terminals)
```

#### ECDSA 2PC with mTLS
See [examples/ecdsa2pc_mtls/](examples/ecdsa2pc_mtls/) for **secure two-party ECDSA** with:
- ✅ Distributed key generation and signing
- ✅ Production-ready mTLS security
- ✅ Complete protocol lifecycle (keygen, sign, refresh)
- ✅ Signature verification and validation
- ✅ Certificate-based authentication
- ✅ Reference session implementation (`examples/mtls_session.go`)

```bash
cd examples/ecdsa2pc_mtls
./generate_certs.sh  # Generate certificates
./run_demo.sh        # Run complete ECDSA 2PC demonstration
```

## Architecture

### Three-Layer Design

```
┌─────────────────────────────────────┐
│   Public API (pkg/mpc)              │  Pure Go, idiomatic interfaces
│   - ECDSA2PC, ECDSAMP               │
│   - Session, KeyShare interfaces    │
└─────────────────────────────────────┘
              │
              │ (minimal interface)
              ▼
┌─────────────────────────────────────┐
│   CGO Bindings (internal/cgo)       │  All CGO complexity isolated here
│   - Opaque C++ handles              │
│   - Memory marshaling               │
└─────────────────────────────────────┘
              │
              │ (C FFI)
              ▼
┌─────────────────────────────────────┐
│   cb-mpc C++ Library                │  Production-grade MPC protocols
│   - Constant-time crypto            │
│   - Formal specifications           │
└─────────────────────────────────────┘
```

### Design Principles

1. **CGO Isolation**: All `import "C"` statements in `internal/cgo` only
2. **Pure Go API**: Public API has zero CGO exposure
3. **Session Abstraction**: Network communication handled in pure Go
4. **Explicit Lifecycle**: Resources use `Close()` pattern, no finalizers
5. **Minimal Crossings**: Batch operations to minimize CGO overhead

## Development

### Building

```bash
# First time setup (builds C++ library - takes ~2 minutes)
make build       # Build C++ library and Go code

# Subsequent builds (fast - skips C++ rebuild)
make test        # Run tests (~0.5s if C++ already built)
make build       # Build Go code only
make examples    # Run example programs

# Force rebuild C++ library (only if needed)
make force-build-cpp
make clean-all   # Clean everything
```

### Project Structure

```
.
├── pkg/mpc/              # Public Go API
│   ├── types.go          # Core types (Session, Curve, etc.)
│   ├── mock_session.go   # In-memory session for testing
│   ├── agree_random.go   # Agree random protocols
│   ├── ecdsa.go          # ECDSA protocols (2PC and MPC)
│   └── *_test.go         # Tests
├── internal/cgo/         # CGO bindings (private, isolated)
│   ├── binding.go        # Core CGO infrastructure & callbacks
│   ├── job.go            # Job (2P/MP) wrappers
│   ├── agree_random.go   # Agree random CGO bindings
│   ├── agree_random.cpp  # C++ wrapper implementations
│   ├── ecdsa_2p.go       # ECDSA 2PC CGO bindings
│   ├── ecdsa_2p.cpp      # ECDSA 2PC C++ wrappers
│   ├── network.h/cpp     # Network callback system
│   └── *.h               # C API headers
├── examples/             # Example programs and utilities
│   ├── doc.go            # Examples package documentation
│   ├── mtls_session.go   # Reference mTLS session implementation
│   ├── agree_random/     # Agree random example
│   └── ecdsa2pc_mtls/    # ECDSA 2PC with mTLS example
├── scripts/              # Build scripts
│   ├── build_cpp.sh      # Build cb-mpc library
│   └── go_with_cpp.sh    # CGO environment wrapper
├── cb-mpc/               # C++ library (git submodule)
└── CLAUDE.md             # Development guide for AI assistants
```

### Testing

```bash
# Run all tests
make test

# Run only Go tests (requires C++ library already built)
make test-short

# Run specific test
bash scripts/go_with_cpp.sh go test -v ./pkg/mpc -run TestLocalSession
```

## Security Considerations

⚠️ **Important Security Notes**

- **Constant-Time**: Crypto operations aim for constant-time execution, but this depends on compiler and CPU architecture
- **Thread Safety**: The C++ library is **NOT thread-safe**. Use proper synchronization when sharing objects across goroutines
- **Key Storage**: Store key shares encrypted at rest. Compromise of all shares allows full key recovery
- **Network Security**: Use authenticated encryption (mTLS) for party-to-party communication
- **Audit**: Review the [specifications](cb-mpc/docs/) and [theory papers](cb-mpc/docs/theory/) before production use

## Performance

CGO calls have ~100-200ns overhead. This library minimizes boundary crossings by:

- Batching operations where possible
- Keeping protocol state in C++
- Using pure Go for all networking

Benchmark results: [Coming Soon]

## Documentation

- **Go API Docs**: [pkg.go.dev](https://pkg.go.dev/github.com/coinbase/cb-mpc-go)
- **Security Testing**: [pkg/mpc/SECURITY_TESTING.md](pkg/mpc/SECURITY_TESTING.md) - Comprehensive malicious party tests
- **C++ Library**: [cb-mpc README](cb-mpc/README.md)
- **Specifications**: [cb-mpc/docs/spec/](cb-mpc/docs/spec/)
- **Theory Papers**: [cb-mpc/docs/theory/](cb-mpc/docs/theory/)
- **Development Guide**: [CLAUDE.md](CLAUDE.md)

## Supported Protocols

| Protocol | Status | Description |
|----------|--------|-------------|
| **Core Protocols** | | |
| Agree Random 2PC | ✅ Ready | Two-party random value agreement |
| Agree Random MPC | ✅ Ready | Multi-party random value agreement (any n ≥ 2) |
| ECDSA 2PC | ✅ Ready | Two-party ECDSA (DKG, sign, refresh) |
| **Threshold Signatures** | | |
| ECDSA MPC | 🚧 Planned | Multi-party threshold ECDSA (t-of-n) |
| Schnorr 2PC | 🚧 Planned | Two-party Schnorr signatures (EdDSA, BIP340) |
| Schnorr MPC | 🚧 Planned | Multi-party Schnorr signatures |
| EdDSA 2PC | 🚧 Planned | Two-party EdDSA (Ed25519, Ed448) |
| EdDSA MPC | 🚧 Planned | Multi-party EdDSA threshold signing |
| **Key Management** | | |
| EC-DKG | 🚧 Planned | Elliptic curve distributed key generation |
| HD Derivation ECDSA 2PC | 🚧 Planned | MPC-friendly BIP32-like derivation for ECDSA |
| HD Derivation EdDSA 2PC | 🚧 Planned | MPC-friendly BIP32-like derivation for EdDSA |
| Key Refresh | 🚧 Planned | Proactive security through key rotation |
| **Backup & Recovery** | | |
| PVE (Base) | 🚧 Planned | Publicly verifiable encryption |
| PVE Batch | 🚧 Planned | Batch publicly verifiable encryption |
| PVE AC | 🚧 Planned | PVE with access control |
| **Zero-Knowledge Proofs** | | |
| ZK Elliptic Curve | 🚧 Planned | Zero-knowledge proofs for EC operations |
| ZK Paillier | 🚧 Planned | Zero-knowledge proofs for Paillier encryption |
| ZK Pedersen | 🚧 Planned | Zero-knowledge proofs for Pedersen commitments |
| ZK ElGamal | 🚧 Planned | Zero-knowledge proofs for ElGamal encryption |
| **Primitives** | | |
| Oblivious Transfer | 🚧 Planned | Base OT and OT extensions |
| Committed Broadcast | 🚧 Planned | Authenticated broadcast with commitments |
| Integer Commitments | 🚧 Planned | Commitment schemes for integers |
| Secret Sharing | 🚧 Planned | Shamir secret sharing and reconstructions |

### Implementation Priority

**🔥 High Priority (Next)**
- ECDSA MPC (threshold ECDSA)
- Schnorr 2PC (EdDSA, BIP340)
- HD Derivation for ECDSA 2PC

**🎯 Medium Priority**
- EdDSA 2PC & MPC
- PVE (Publicly Verifiable Encryption)
- EC-DKG (standalone distributed key generation)

**📋 Lower Priority**
- Advanced ZK proofs
- Oblivious Transfer primitives
- Specialized commitment schemes

> **Note**: All protocols listed are available in the underlying [cb-mpc C++ library](https://github.com/coinbase/cb-mpc). This roadmap reflects Go wrapper implementation priorities. Contributions welcome!

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This project is licensed under the same terms as [cb-mpc](https://github.com/coinbase/cb-mpc). See [LICENSE.md](LICENSE.md).

## Acknowledgments

Built on top of Coinbase's open-source MPC library. Special thanks to the Coinbase cryptography team for their rigorous specifications and production-hardened implementation.
