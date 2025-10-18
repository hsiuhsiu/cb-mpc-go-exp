# Claude Code Development Guide

This document provides guidelines for working with this codebase, particularly for adding new protocol wrappers from the cb-mpc C++ submodule.

## Project Structure

This is a Go wrapper project for the cb-mpc C++ library located in the `cb-mpc/` submodule. The project uses CGO to bind Go code to the underlying C++ implementation.

### Key Directories

- `cb-mpc/` - Git submodule containing the C++ MPC protocol implementations
- `internal/bindings/` - CGO bindings layer (C headers, C++ wrappers, Go bindings)
- `pkg/cbmpc/` - Public Go API exposed to users
- `pkg/cbmpc/mocknet/` - Mock network implementation for testing

## Adding New Protocol Wrappers

When adding new protocol wrappers based on C++ implementations in the cb-mpc submodule, follow these steps:

### Step 1: Check the C++ Protocol Interface

First, examine the C++ protocol header in `cb-mpc/src/cbmpc/protocol/` to understand:
- Function signatures
- Input/output types (e.g., `buf_t`, `std::vector<buf_t>`)
- Whether it's a 2-party (`job_2p_t`) or multi-party (`job_mp_t`) protocol

Example: `cb-mpc/src/cbmpc/protocol/agree_random.h`

### Step 2: Add C Function Declarations

Add C function declarations to `internal/bindings/capi.h`:

```c
int cbmpc_protocol_name(cbmpc_jobmp *j, /* parameters */, cmem_t *out);
```

**Important memory types:**
- `cmem_t` - Single buffer (has `data` and `size` fields)
- `cmems_t` - Multiple buffers (has `data`, `sizes`, and `count` fields)

### Step 3: Implement C++ Wrapper Functions

Add wrapper implementations to `internal/bindings/capi.cc`:

```cpp
int cbmpc_protocol_name(cbmpc_jobmp *j, /* parameters */, cmem_t *out) {
  auto wrapper = reinterpret_cast<go_jobmp *>(j);
  if (!wrapper || !wrapper->job || !out) return E_BADARG;
  buf_t result;
  error_t rv = coinbase::mpc::protocol_name(*wrapper->job, /* args */, result);
  if (rv != SUCCESS) {
    return rv;
  }
  *out = alloc_and_copy(result.data(), static_cast<size_t>(result.size()));
  return 0;
}
```

**For vector outputs** (returning `std::vector<buf_t>`), use `cmems_t` and `alloc_and_copy_vector()`:

```cpp
int cbmpc_protocol_name(cbmpc_jobmp *j, /* parameters */, cmems_t *out) {
  auto wrapper = reinterpret_cast<go_jobmp *>(j);
  if (!wrapper || !wrapper->job || !out) return E_BADARG;
  std::vector<buf_t> result;
  error_t rv = coinbase::mpc::protocol_name(*wrapper->job, /* args */, result);
  if (rv != SUCCESS) {
    return rv;
  }
  *out = alloc_and_copy_vector(result);
  return 0;
}
```

### Step 4: Add Go Binding Functions

Add binding functions to `internal/bindings/bindings_protocol.go`:

```go
// ProtocolName is a C binding wrapper for the protocol.
func ProtocolName(cj unsafe.Pointer, /* params */) ([]byte, error) {
	if cj == nil {
		return nil, errors.New("nil job")
	}
	var out C.cmem_t
	rc := C.cbmpc_protocol_name((*C.cbmpc_jobmp)(cj), /* args */, &out)
	if rc != 0 {
		return nil, errors.New("protocol_name failed")
	}
	return cmemToGoBytes(out), nil
}
```

**For vector outputs**, use `cmems_t` and `cmemsToGoByteSlices()`:

```go
func ProtocolName(cj unsafe.Pointer, /* params */) ([][]byte, error) {
	if cj == nil {
		return nil, errors.New("nil job")
	}
	var out C.cmems_t
	rc := C.cbmpc_protocol_name((*C.cbmpc_jobmp)(cj), /* args */, &out)
	if rc != 0 {
		return nil, errors.New("protocol_name failed")
	}
	return cmemsToGoByteSlices(out), nil
}
```

### Step 5: Add Stub Implementations

Add stub implementations to `internal/bindings/bindings_stub.go` for non-CGO builds:

```go
func ProtocolName(unsafe.Pointer, /* params */) ([]byte, error) {
	return nil, ErrNotBuilt
}
```

### Step 6: Add Public Go API

Add public API functions to the appropriate file in `pkg/cbmpc/` (e.g., `agree_random.go`, `sign.go`):

```go
// ProtocolName is a Go wrapper for coinbase::mpc::protocol_name.
// See cb-mpc/src/cbmpc/protocol/[protocol_file].h for protocol details.
func ProtocolName(_ context.Context, j *JobMP, /* params */) ([]byte, error) {
	// Only validate Go-specific concerns (like nil pointers)
	// Do NOT validate business logic (like bitlen ranges)
	if j == nil {
		return nil, errors.New("nil job")
	}

	ptr, err := j.ptr()
	if err != nil {
		return nil, err
	}

	out, err := bindings.ProtocolName(ptr, /* args */)
	if err != nil {
		return nil, remapError(err)
	}
	runtime.KeepAlive(j)
	return out, nil
}
```

**Important:**
- Always include `runtime.KeepAlive(j)` to prevent premature garbage collection
- Only validate Go-level concerns (nil checks), not business logic parameters
- Keep comments minimal - just reference the C++ function and header file

### Step 7: Add Unit Tests

Add comprehensive unit tests to the corresponding test file in `pkg/cbmpc/`:

```go
func TestProtocolNameNative(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	net := mocknet.New()

	// Set up roles, names, and jobs
	roles := []cbmpc.RoleID{0, 1, 2}
	names := []string{"p1", "p2", "p3"}

	// Create jobs for each party
	// Run protocol in goroutines
	// Verify outputs
}
```

**Test considerations:**
- Use `mocknet.New()` for network simulation
- Run protocol calls in parallel using goroutines and `sync.WaitGroup`
- Verify output correctness (length, consistency across parties, etc.)
- For pairwise protocols, verify pairwise consistency

### Step 8: Update Documentation

Update package documentation to reflect the new protocol:

1. **Update doc.go** (if in existing package):
   - Add new function to "Available Protocols" or "Key Operations" list
   - Update usage example if showing typical workflow
   - Keep under 100 lines total

2. **Create doc.go** (if new package):
   - Follow template in "Documentation Guidelines" section below
   - Include package overview, operations list, memory management, usage example
   - Keep it 50-90 lines depending on complexity

3. **Update or create README.md** (if applicable):
   - Only if package has complex security model or multiple related protocols
   - Add protocol section with detailed example and use cases
   - See "When to Create a README.md" section below

4. **Verify accuracy**:
   ```bash
   # Check all listed functions exist
   grep "^func [A-Z]" pkg/cbmpc/yourpackage/*.go

   # Verify doc.go length is reasonable
   wc -l pkg/cbmpc/yourpackage/doc.go
   ```

See the [Documentation Guidelines](#documentation-guidelines) section below for detailed instructions.

## Memory Management

### C++ to Go Memory Conversion

The conversion helpers in `internal/bindings/bindings_types.go` handle memory safely:

- `cmemToGoBytes(C.cmem_t)` - Converts single buffer, securely zeros and frees C memory
- `cmemsToGoByteSlices(C.cmems_t)` - Converts multiple buffers, securely zeros and frees C memory

These functions take ownership of C memory and handle cleanup automatically.

### Go to C Memory Conversion

There are two ways to pass Go data to C, depending on the use case:

#### Option 1: `goBytesToCmem([]byte)` - Zero-copy pointer to Go memory

Creates a `cmem_t` pointing directly to Go memory (no allocation).

**Use when:**
- C function completes synchronously and quickly
- Input parameters are only read during the immediate C call
- No risk of Go GC moving memory during operation

**Examples:** DKG, AgreeRandom, serialization/deserialization

```go
func ECDSA2PDKG(cj unsafe.Pointer, curveNID int) (ECDSA2PKey, error) {
    // goBytesToCmem for fast, synchronous operations
    var key ECDSA2PKey
    rc := C.cbmpc_ecdsa2p_dkg((*C.cbmpc_job2p)(cj), C.int(curveNID), &key)
    // No need to free - no allocation happened
    return key, nil
}
```

**Important:** The returned `cmem_t` points to Go memory and is only valid for the duration of the CGO call. Do not retain the `cmem_t` beyond the CGO function call.

#### Option 2: `allocCmem([]byte)` + `defer freeCmem()` - C-allocated copy

Allocates C memory and copies Go data into it.

**Use when:**
- C function is long-running (network I/O, multi-round protocols)
- Input parameters might be accessed after initial function call
- C code might retain pointers beyond immediate use
- Go GC could move memory while C code is still executing

**Examples:** Sign operations (all variants), batch operations

```go
func ECDSA2PSign(cj unsafe.Pointer, key ECDSA2PKey, sidIn, msg []byte) ([]byte, []byte, error) {
    // Copy inputs into C-allocated memory to avoid aliasing Go memory during CGO call
    sidMem := allocCmem(sidIn)
    defer freeCmem(sidMem)
    msgMem := allocCmem(msg)
    defer freeCmem(msgMem)

    var sidOut, sigOut C.cmem_t
    rc := C.cbmpc_ecdsa2p_sign((*C.cbmpc_job2p)(cj), sidMem, key, msgMem, &sidOut, &sigOut)

    // sidMem and msgMem are automatically freed by defer
    // Only outputs allocated by C need conversion
    return cmemToGoBytes(sidOut), cmemToGoBytes(sigOut), nil
}
```

**Important:** Always use `defer freeCmem()` immediately after `allocCmem()` to ensure cleanup on all code paths (including errors).

### C++ Memory Allocation Helpers

In `internal/bindings/capi.cc`:

- `alloc_and_copy()` - Allocates and copies a single buffer to `cmem_t`
- `alloc_and_copy_vector()` - Allocates and copies multiple buffers to `cmems_t`

## Build and Test Commands

```bash
# Run all tests (requires CGO)
make test

# Run linter (requires CGO for type checking)
make lint

# Check for vulnerabilities (CGO disabled)
make vuln

# Run security scan
make sec

# Build with Docker
CBMPC_USE_DOCKER=1 make test
```

**Before submitting changes, ensure all checks pass:**
```bash
make test && make lint && make vuln && make sec
```

**Note:** The linter requires OpenSSL headers to be available. If you get OpenSSL-related errors:
```bash
# For host builds
make openssl

# For docker builds
CBMPC_USE_DOCKER=1 make openssl
```

The `make bootstrap` target (run in CI) automatically builds OpenSSL as part of building cb-mpc.

### Build System

The build system supports two flavors:
- **host** (default): Builds using host-native OpenSSL in `build/openssl-host/`
- **docker**: Builds using Docker with OpenSSL in `build/openssl-docker/`

The flavor is controlled by `CBMPC_USE_DOCKER` environment variable and automatically sets:
- `CBMPC_ENV_FLAVOR` - Set to `host` or `docker`
- `CGO_CFLAGS` - Includes appropriate OpenSSL include path
- `CGO_CXXFLAGS` - Includes appropriate OpenSSL include path
- `CGO_LDFLAGS` - Includes appropriate OpenSSL library path

This avoids linker warnings about missing search paths by only including the relevant paths for the active build flavor.

## Common Patterns

### Parameter Validation Philosophy

**This is a thin Go wrapper around C++ functions. Only validate Go-specific concerns, not business logic.**

✅ **DO validate:**
- Nil job pointers (`j == nil`) - This is a Go-level safety check
- Other Go-specific wrapping concerns

❌ **DO NOT validate:**
- Parameter values like `bitlen`, thresholds, sizes, etc.
- Business logic constraints
- Protocol-specific validation

**Rationale:** The C++ layer already performs comprehensive validation. Duplicating validation in Go:
- Creates maintenance burden (two places to update)
- Can lead to inconsistencies between layers
- Adds unnecessary overhead
- May become outdated if C++ validation changes

Let the C++ layer handle all business logic validation and return appropriate errors.

### Error Handling

Use `remapError()` to convert internal errors to public errors before returning from public API functions.

### Access Control Structures

When working with threshold protocols that use access control structures, always use the `accessstructure` package types, not raw `[]byte`.

**✅ CORRECT Pattern:**

```go
import (
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
	ac "github.com/coinbase/cb-mpc-go/pkg/cbmpc/accessstructure"  // Import with alias
)

// ThresholdDKGParams contains parameters for threshold DKG.
type ThresholdDKGParams struct {
	Curve              cbmpc.Curve
	AccessStructure    ac.AccessStructure  // Use the typed AccessStructure
	QuorumPartyIndices []int
}

func ThresholdDKG(ctx context.Context, j *cbmpc.JobMP, params *ThresholdDKGParams) (*ThresholdDKGResult, error) {
	// AccessStructure is already []byte under the hood, so just convert it
	keyPtr, sid, err := backend.ThresholdDKG(ptr, nid, []byte(params.AccessStructure), params.QuorumPartyIndices)
	// ...
}
```

**❌ INCORRECT Pattern:**

```go
// DON'T use []byte directly
type ThresholdDKGParams struct {
	Curve              cbmpc.Curve
	AccessStructure    []byte  // ❌ Don't use raw []byte
	QuorumPartyIndices []int
}
```

**Why use `ac.AccessStructure` instead of `[]byte`?**

1. **Type Safety**: Makes it clear that the parameter expects a compiled access structure, not arbitrary bytes
2. **Better Documentation**: Users can see what type to use without reading detailed comments
3. **API Consistency**: All threshold functions use the same type across packages
4. **Future-Proofing**: If the access structure representation changes, only one place needs updating

**Standard Import Alias:**

Always use `ac` as the import alias for `pkg/cbmpc/accessstructure` to keep code concise:

```go
import ac "github.com/coinbase/cb-mpc-go/pkg/cbmpc/accessstructure"
```

This allows using `ac.AccessStructure`, `ac.Compile()`, `ac.Leaf()`, etc. throughout your code.

**Note:** `AccessStructure` is defined as `type AccessStructure []byte` in the accessstructure package, so it's still just bytes under the hood. However, using the type makes the API clearer and more maintainable.

### CGO Build Tags

All CGO-dependent files must have:
```go
//go:build cgo && !windows
```

All stub files must have:
```go
//go:build !cgo || windows
```

## API Design Patterns

### Params/Result Pattern for Complex Protocols

For protocols with multiple inputs/outputs or in/out parameters, use **Params** and **Result** structs:

**When to use:**
- Protocols with 3+ input parameters
- Protocols with in/out parameters (e.g., session IDs that get updated)
- Protocols returning multiple values
- Batch operations

**Pattern:**
```go
// DKGParams contains parameters for distributed key generation.
type DKGParams struct {
    Curve Curve
}

// DKGResult contains the output of distributed key generation.
type DKGResult struct {
    Key *ECDSA2PKey
}

// DKG performs 2-party ECDSA distributed key generation.
// See cb-mpc/src/cbmpc/protocol/ecdsa_2p.h for protocol details.
func DKG(ctx context.Context, j *Job2P, params *DKGParams) (*DKGResult, error)
```

**For in/out parameters (like session IDs):**
```go
// SignParams contains parameters for signing.
type SignParams struct {
    SessionID []byte      // In/out parameter
    Key       *ECDSA2PKey
    Message   []byte
}

// SignResult contains the output of signing.
type SignResult struct {
    SessionID []byte // Updated session ID
    Signature []byte
}

func Sign(ctx context.Context, j *Job2P, params *SignParams) (*SignResult, error)
```

**Benefits:**
- Clean, self-documenting API
- Easy to extend without breaking compatibility
- Handles in/out parameters naturally
- Groups related parameters logically

### Simple Protocol Pattern

For simple protocols with 1-2 inputs and a single output, use direct parameters:

```go
// AgreeRandom is a Go wrapper for coinbase::mpc::agree_random.
func AgreeRandom(ctx context.Context, j *Job2P, bitlen int) ([]byte, error)
```

### Opaque Type Pattern with C++ Getters

For complex C++ types (like `key_t`), store serialized bytes and implement getters in C++:

**Go side:**
```go
// ECDSA2PKey represents a 2-party ECDSA key share.
// The key is stored in serialized form and all operations are delegated to C++.
type ECDSA2PKey struct {
    serialized []byte
}

// Bytes returns the serialized key.
func (k *ECDSA2PKey) Bytes() []byte {
    return k.serialized
}

// PublicKey extracts the public key point Q.
func (k *ECDSA2PKey) PublicKey() ([]byte, error) {
    return bindings.ECDSA2PKeyGetPublicKey(k.serialized)
}
```

**C++ side (in capi.cc):**
```cpp
int cbmpc_ecdsa2p_key_get_public_key(cmem_t serialized_key, cmem_t *out) {
    // Deserialize key using converter_t
    // Extract Q point
    // Serialize Q to bytes
    // Return via out
}
```

**Benefits:**
- Keeps Go layer thin
- All validation/logic stays in C++
- Type-safe in Go
- Easy to add new getters

## Type Mappings

### C++ to C to Go

| C++ Type | C Type | Go Type |
|----------|--------|---------|
| `buf_t` | `cmem_t` | `[]byte` |
| `std::vector<buf_t>` | `cmems_t` | `[][]byte` |
| `job_2p_t*` | `cbmpc_job2p*` | `*Job2P` |
| `job_mp_t*` | `cbmpc_jobmp*` | `*JobMP` |
| `ecurve_t` | `int` (NID) | `Curve` (struct with NID) |
| `key_t` (serialized) | `cmem_t` | `*ECDSA2PKey` (opaque bytes) |
| `int` | `int` | `int` |
| `error_t` | `int` (return code) | `error` |

## Type Conversion Patterns

This section documents the established conventions for converting between C++ types, C types, and Go types across the FFI boundary.

### Philosophy: Minimize Layering and Let C++ Handle Serialization

**Core Principle:** Keep the Go layer thin. All serialization/deserialization should happen in C++, and Go should work with simple byte slices whenever possible.

**Why?**
- Reduces complexity and maintenance burden
- Leverages existing `coinbase::ser()` and `coinbase::deser()` functions
- Avoids creating unnecessary opaque types and handle management in Go
- Makes the API more Go-idiomatic (working with `[]byte`)

### Pattern 1: Simple Data Types (buf_t)

**Use for:** Protocol outputs, simple data buffers

**C++ → Go:**
```cpp
// In capi.cc
int cbmpc_protocol_name(..., cmem_t *out) {
    buf_t result;
    error_t rv = coinbase::mpc::protocol_name(..., result);
    if (rv != SUCCESS) return rv;
    *out = alloc_and_copy(result.data(), static_cast<size_t>(result.size()));
    return 0;
}
```

```go
// In bindings_protocol.go
func ProtocolName(...) ([]byte, error) {
    var out C.cmem_t
    rc := C.cbmpc_protocol_name(..., &out)
    if rc != 0 {
        return nil, formatNativeErr("protocol_name", rc)
    }
    return cmemToGoBytes(out), nil
}
```

**Public API:**
```go
// In pkg/cbmpc/
func ProtocolName(ctx context.Context, j *JobMP, ...) ([]byte, error) {
    ptr, err := j.ptr()
    if err != nil {
        return nil, err
    }
    out, err := backend.ProtocolName(ptr, ...)
    if err != nil {
        return nil, RemapError(err)
    }
    runtime.KeepAlive(j)
    return out, nil
}
```

### Pattern 2: Vector Data Types (std::vector<buf_t>)

**Use for:** Multi-party outputs, batch operations

**C++ → Go:**
```cpp
// In capi.cc
int cbmpc_protocol_name(..., cmems_t *out) {
    std::vector<buf_t> results;
    error_t rv = coinbase::mpc::protocol_name(..., results);
    if (rv != SUCCESS) return rv;
    *out = alloc_and_copy_vector(results);
    return 0;
}
```

```go
// In bindings_protocol.go
func ProtocolName(...) ([][]byte, error) {
    var out C.cmems_t
    rc := C.cbmpc_protocol_name(..., &out)
    if rc != 0 {
        return nil, formatNativeErr("protocol_name", rc)
    }
    return cmemsToGoByteSlices(out), nil
}
```

### Pattern 3: Complex C++ Types with Serialization

**Use for:** Types that have `coinbase::ser()` / `coinbase::deser()` support (e.g., `zk::uc_dl_t`, `key_t`)

**Core Idea:** Serialize in C++, pass as bytes to Go, deserialize in C++ when needed. Go only sees `[]byte`.

**Example: ZK Proofs**

```cpp
// In capi.cc - Prove operation
int cbmpc_uc_dl_prove(cbmpc_ecc_point Q_point, cmem_t w, cmem_t session_id,
                      uint64_t aux, cmem_t *proof_out) {
    // Create proof object
    coinbase::zk::uc_dl_t proof;
    proof.prove(...);

    // Serialize to bytes immediately
    buf_t serialized = coinbase::ser(proof);
    *proof_out = alloc_and_copy(serialized.data(), serialized.size());
    return 0;
}

// In capi.cc - Verify operation
int cbmpc_uc_dl_verify(cmem_t proof_bytes, cbmpc_ecc_point Q_point,
                       cmem_t session_id, uint64_t aux) {
    // Deserialize from bytes
    coinbase::zk::uc_dl_t proof;
    error_t rv = coinbase::deser(mem_t(proof_bytes.data, proof_bytes.size), proof);
    if (rv != SUCCESS) return rv;

    // Use the object
    return proof.verify(...);
}
```

```go
// In bindings_protocol.go
func UCDLProve(...) ([]byte, error) {
    var out C.cmem_t
    rc := C.cbmpc_uc_dl_prove(..., &out)
    if rc != 0 {
        return nil, formatNativeErr("uc_dl_prove", rc)
    }
    return cmemToGoBytes(out), nil
}

func UCDLVerify(proof []byte, ...) error {
    proofMem := goBytesToCmem(proof)
    rc := C.cbmpc_uc_dl_verify(proofMem, ...)
    if rc != 0 {
        return formatNativeErr("uc_dl_verify", rc)
    }
    return nil
}
```

```go
// In public API
type DLProof []byte  // Just a type alias for clarity

func Prove(params *DLProveParams) (DLProof, error) {
    proofBytes, err := backend.UCDLProve(...)
    return DLProof(proofBytes), err
}

func Verify(params *DLVerifyParams) error {
    return backend.UCDLVerify([]byte(params.Proof), ...)
}
```

**Anti-pattern (DON'T DO THIS):**
```go
// ❌ Don't create opaque pointer types in Go for serializable C++ types
type UCDLProof = C.cbmpc_uc_dl_proof  // BAD

// ❌ Don't expose separate serialization functions
func UCDLProofToBytes(UCDLProof) ([]byte, error)   // BAD
func UCDLProofFromBytes([]byte) (UCDLProof, error) // BAD
func UCDLProofFree(UCDLProof)                       // BAD
```

### Pattern 4: Opaque Native Handles (Non-Serializable Types)

**Use for:** Types that cannot be serialized or are expensive to serialize (e.g., `ecc_point_t`, `bn_t`, `key_t` when used as handle)

**When to use opaque handles:**
- Type is frequently passed between operations without modification
- Serialization/deserialization is expensive
- Type maintains internal state that's costly to recreate

**C++ → Go:**
```cpp
// In capi.h
typedef void* cbmpc_ecc_point;

// In capi.cc
int cbmpc_ecc_point_from_bytes(int curve_nid, cmem_t bytes, cbmpc_ecc_point *point_out) {
    auto point = std::make_unique<coinbase::crypto::ecc_point_t>();
    error_t rv = point->from_oct(...);
    if (rv != SUCCESS) return rv;
    *point_out = reinterpret_cast<cbmpc_ecc_point>(point.release());
    return 0;
}

void cbmpc_ecc_point_free(cbmpc_ecc_point point) {
    if (point) {
        auto* ecc_point = reinterpret_cast<coinbase::crypto::ecc_point_t*>(point);
        delete ecc_point;
    }
}
```

```go
// In bindings_protocol.go
type ECCPoint = C.cbmpc_ecc_point

func ECCPointFromBytes(curveNID int, bytes []byte) (ECCPoint, error) {
    bytesMem := goBytesToCmem(bytes)
    var point ECCPoint
    rc := C.cbmpc_ecc_point_from_bytes(C.int(curveNID), bytesMem, &point)
    if rc != 0 {
        return nil, errors.New("ecc_point_from_bytes failed")
    }
    return point, nil
}

func ECCPointFree(point ECCPoint) {
    if point != nil {
        C.cbmpc_ecc_point_free(point)
    }
}
```

```go
// In public API (pkg/cbmpc/curve/point.go)
type Point struct {
    cptr unsafe.Pointer  // Holds ECCPoint
}

func (p *Point) Free() {
    if p.cptr != nil {
        backend.ECCPointFree(backend.ECCPoint(p.cptr))
        p.cptr = nil
    }
}

// Use finalizer for safety
func NewPointFromBytes(curve Curve, bytes []byte) (*Point, error) {
    cpoint, err := backend.ECCPointFromBytes(curve.NID(), bytes)
    if err != nil {
        return nil, err
    }
    p := &Point{cptr: unsafe.Pointer(cpoint)}
    runtime.SetFinalizer(p, (*Point).Free)
    return p, nil
}
```

### Pattern 5: Stateful Objects with Getters

**Use for:** Complex objects where you need to extract specific fields (e.g., `ECDSA2PKey`)

**Approach:** Keep C++ object as opaque handle, provide getter functions in C++ to extract fields.

```cpp
// In capi.cc
int cbmpc_ecdsa2p_key_get_public_key(const cbmpc_ecdsa2p_key *key, cmem_t *out) {
    if (!key || !key->opaque || !out) return E_BADARG;

    const auto* cpp_key = static_cast<const coinbase::mpc::ecdsa2pc::key_t*>(key->opaque);

    // Extract public key point
    const auto& Q = cpp_key->get_Q();
    buf_t Q_bytes = Q.to_oct();

    *out = alloc_and_copy(Q_bytes.data(), Q_bytes.size());
    return 0;
}
```

```go
// In public API
type ECDSA2PKey struct {
    handle backend.ECDSA2PKey
}

func (k *ECDSA2PKey) PublicKey() ([]byte, error) {
    return backend.ECDSA2PKeyGetPublicKey(k.handle)
}

func (k *ECDSA2PKey) Curve() (Curve, error) {
    return backend.ECDSA2PKeyGetCurve(k.handle)
}
```

### Decision Tree: Which Pattern to Use?

```
Is the type a simple buffer (buf_t)?
├─ Yes → Pattern 1 (Simple Data)
└─ No → Is it a vector of buffers (std::vector<buf_t>)?
    ├─ Yes → Pattern 2 (Vector Data)
    └─ No → Does the type have coinbase::ser/deser support?
        ├─ Yes → Pattern 3 (Serializable Complex Types)
        │         Examples: zk::uc_dl_t, signature types
        └─ No → Is serialization expensive or type is frequently reused?
            ├─ Yes → Pattern 4 (Opaque Handles)
            │         Examples: ecc_point_t, bn_t
            └─ No → Does it need field extraction?
                ├─ Yes → Pattern 5 (Stateful with Getters)
                │         Examples: key_t
                └─ No → Consider adding coinbase::ser/deser
                          and use Pattern 3
```

### Key Takeaways

1. **Default to Pattern 3** for new complex types - serialize in C++, work with `[]byte` in Go
2. **Use opaque handles (Pattern 4)** only when serialization is genuinely expensive
3. **Always handle memory correctly:**
   - `cmemToGoBytes()` takes ownership of C memory and frees it
   - `goBytesToCmem()` creates zero-copy view (fast, synchronous ops only)
   - `allocCmem()` + `defer freeCmem()` for long-running C operations
4. **Document the pattern** when adding new types so future maintainers understand the choice

## Documentation Guidelines

This section describes how to write high-quality documentation for packages and protocols.

### Overview

cb-mpc-go uses two forms of documentation:
1. **doc.go files** - Package-level documentation displayed in pkgsite and godoc
2. **README.md files** - Supplementary detailed documentation for complex packages (optional)

Both should be **clear, accurate, and succinct** - avoiding verbosity while providing essential information.

---

## Writing doc.go Files

Every public package in `pkg/cbmpc/` must have a `doc.go` file with package-level documentation.

### Template Structure

```go
// Package <name> provides <one-line description>.
//
// <2-3 sentence overview explaining what the package does and why it exists>
//
// # <Section 1 - e.g., "Available Protocols" or "Key Types">
//
// <Bulleted list or brief description>
//
// # <Section 2 - e.g., "Memory Management" or "Usage">
//
// <Key information users need to know>
//
// # Usage Example (if helpful)
//
//	// Minimal, compilable code example
//	result, err := packagename.Function(ctx, params)
//
// See cb-mpc/src/cbmpc/protocol/<file>.h for protocol implementation details.
package <name>
```

### doc.go Best Practices

**Length Guidelines:**
- Simple packages (utilities, helpers): 12-30 lines
- Protocol packages (agreerandom, ecdsa2p): 50-75 lines
- Complex packages (pve, mocknet, logging): 75-90 lines
- Never exceed 100 lines - if you need more, create a README.md

**Content Guidelines:**

✅ **DO include:**
- One-line package summary (first sentence is critical for search/listings)
- List of available functions/operations (bullet points)
- Memory management requirements (if resources need cleanup)
- Minimal usage example showing typical API usage
- Reference to C++ header for protocol details
- Security warnings (if applicable, e.g., kem package)

❌ **DO NOT include:**
- Detailed algorithm descriptions
- Parameter validation rules
- Complete API reference (users can click through to function docs)
- Multiple examples for different scenarios
- Copy-pasted C++ documentation

**Style:**
- Use present tense ("provides", "implements", "allows")
- Be direct and factual, avoid marketing language
- Use bullet points for lists of items
- Use code blocks sparingly (1-2 maximum)
- Keep paragraphs short (2-3 sentences)

### Examples by Package Type

**Simple Protocol Package** (agreerandom - 27 lines):
```go
// Package agreerandom provides secure multi-party random value agreement protocols.
//
// This package implements various protocols for two or more parties to jointly
// generate shared random values without requiring trust in any single party.
// Each protocol provides different security guarantees and is suitable for
// different use cases in secure multi-party computation.
//
// # Available Protocols
//
//   - AgreeRandom: Two-party random agreement (fully secure)
//   - MultiAgreeRandom: Multi-party random agreement (fully secure)
//   - WeakMultiAgreeRandom: Multi-party random agreement (faster, weaker security)
//   - MultiPairwiseAgreeRandom: Multi-party pairwise random agreement (fully secure)
//
// # Usage
//
//	// Two-party example
//	random, err := agreerandom.AgreeRandom(ctx, job2P, 256)
//
//	// Multi-party example
//	random, err := agreerandom.MultiAgreeRandom(ctx, jobMP, 256)
//
// See cb-mpc/src/cbmpc/protocol/agree_random.h for protocol implementation details.
package agreerandom
```

**Complex Protocol Package** (ecdsa2p - 71 lines):
- Includes security model section
- Lists all operations (DKG, Sign, SignBatch, etc.)
- Shows memory management with `defer Close()`
- Provides complete workflow example
- References C++ header

**Infrastructure Package** (mocknet - 89 lines):
- Explains what it's for (testing/examples)
- Lists key features
- Shows setup for both 2-party and multi-party
- Includes testing tips
- States limitations (not for production)

---

## When to Create a README.md

Create a README.md file in addition to doc.go when:

1. **Complex Security Model** - Package has critical security considerations (e.g., kem package)
2. **Multiple Proof Types** - Package provides several related but distinct protocols (e.g., zk package)
3. **Non-Obvious Usage** - Typical usage requires significant explanation
4. **Algorithmic Details** - Users benefit from understanding "what" and "why" (not just "how")

**Currently only 2 packages have READMEs:**
- `pkg/cbmpc/zk/README.md` (154 lines) - Documents 4 different ZK proof protocols
- `pkg/cbmpc/kem/README.md` (364 lines) - Critical security warnings about deterministic KEMs

### README.md Structure

```markdown
# Package Name

<1-2 sentence overview>

**SECURITY WARNING** (if applicable)

## Available Protocols/Operations

- Protocol 1: Brief description
- Protocol 2: Brief description

## Protocol 1 - Descriptive Name

<2-3 sentences explaining what it does>

### Features (optional)

- Feature 1
- Feature 2

### Usage

\`\`\`go
// Complete, runnable example
\`\`\`

### Use Cases (optional)

When to use this protocol:
- Use case 1
- Use case 2

## Protocol 2 - Descriptive Name

<Repeat structure>

## Common Patterns (if applicable)

<Shared concepts across protocols>

## Security Properties (if applicable)

<Security guarantees and limitations>

## References

- C++ header: cb-mpc/src/cbmpc/...
- Academic papers (if relevant)
```

### README Best Practices

✅ **DO:**
- Start with critical warnings (security, platform support)
- Provide complete, runnable code examples
- Explain "what" and "why", not just "how"
- Use consistent formatting across protocols
- Include use cases for when to use each variant

❌ **DON'T:**
- Duplicate information already in doc.go
- Write tutorial-style step-by-step guides
- Include exhaustive parameter documentation
- Exceed 400 lines (split into multiple docs if needed)

---

## Maintaining Documentation Accuracy

When adding new protocols or modifying existing ones, **verify documentation remains accurate**.

### Checklist for New Protocols

When adding a new protocol wrapper:

1. **Create or update doc.go**
   - [ ] Add new function to "Available Protocols" or "Key Operations" list
   - [ ] Update usage example if function signature changes
   - [ ] Verify line count stays within guidelines (< 100 lines)

2. **Update README.md** (if package has one)
   - [ ] Add new protocol section with usage example
   - [ ] Update table of contents
   - [ ] Verify all code examples are accurate

3. **Verify accuracy**
   - [ ] All listed functions actually exist (use `grep "^func" pkg/cbmpc/package/*.go`)
   - [ ] No outdated function names remain
   - [ ] Interface definitions match actual code
   - [ ] Parameter types in examples are correct

### Common Mistakes to Avoid

**❌ Listing non-existent functions:**
```go
// # Key Operations
//   - SignBatch: Batch signing  // ❌ Function doesn't exist!
```

**❌ Outdated interface definitions:**
```go
// type KEM interface {
//     Generate() ([]byte, []byte, error)  // ❌ Method removed!
// }
```

**❌ Missing new operations:**
```go
// # Key Operations
//   - DKG
//   - Sign
//   // ❌ Missing: SignBatch, Refresh
```

### Verification Commands

Before committing documentation:

```bash
# Verify all functions listed in doc.go exist
grep "func [A-Z]" pkg/cbmpc/packagename/*.go

# Check interface definitions match
grep -A 10 "^type.*interface" pkg/cbmpc/packagename/*.go

# Count doc.go lines (should be < 100)
wc -l pkg/cbmpc/*/doc.go
```

### When Documentation Becomes Stale

Documentation can become inaccurate when:
- New functions are added without updating doc.go
- Functions are renamed or removed
- Interfaces change
- Parameter types or return values change

**Fix stale documentation immediately** when you notice it. Inaccurate docs are worse than no docs.

---

## Documentation Standards

**Keep documentation minimal and focused on the wrapping layer, not protocol logic.**

### Function Documentation Philosophy

Following the thin-wrapper principle, function comments should:

✅ **DO include:**
- Reference to the underlying C++ function (e.g., `coinbase::mpc::function_name`)
- Link to C++ header file for protocol details
- Go-specific type conversions if non-obvious (e.g., `std::vector<buf_t>` → `[][]byte`)

❌ **DO NOT include:**
- Detailed protocol descriptions
- Parameter constraints and validation rules
- Algorithm explanations
- Business logic details

**Rationale:** Protocol documentation belongs in the C++ layer. Duplicating it in Go comments:
- Creates maintenance burden (two places to update)
- Can become outdated when C++ changes
- Adds unnecessary verbosity

### Good Examples

**Simple wrapper (single return value):**
```go
// AgreeRandom is a Go wrapper for coinbase::mpc::agree_random.
// See cb-mpc/src/cbmpc/protocol/agree_random.h for protocol details.
func AgreeRandom(_ context.Context, j *Job2P, bitlen int) ([]byte, error)
```

**Wrapper with type conversion note:**
```go
// MultiPairwiseAgreeRandom is a Go wrapper for coinbase::mpc::multi_pairwise_agree_random.
// Returns a slice of []byte corresponding to the C++ std::vector<buf_t> output.
// See cb-mpc/src/cbmpc/protocol/agree_random.h for protocol details.
func MultiPairwiseAgreeRandom(_ context.Context, j *JobMP, bitlen int) ([][]byte, error)
```

### Bad Example (Too Much Detail)

```go
// ❌ DON'T DO THIS
// MultiPairwiseAgreeRandom performs a multi-party pairwise agree random protocol.
// Returns a slice of n random values (one for each party including self), where each value is bitlen bits.
// The random value at index i is shared between the calling party and party i.
// Party i's output at index j matches party j's output at index i (pairwise consistency).
// The bitlen must be a multiple of 8 and at least 8.
func MultiPairwiseAgreeRandom(_ context.Context, j *JobMP, bitlen int) ([][]byte, error)
```

## Examples

See the implementation of agree_random protocols for complete examples:
- `internal/bindings/capi.h` - C declarations
- `internal/bindings/capi.cc` - C++ wrappers
- `internal/bindings/bindings_protocol.go` - Go bindings (CGO)
- `internal/bindings/bindings_stub.go` - Go stubs (non-CGO)
- `pkg/cbmpc/agree_random.go` - Public API
- `pkg/cbmpc/agree_random_test.go` - Tests

## Troubleshooting

### Build Errors

1. **"undefined reference"** - Check that C function is declared in `capi.h` and implemented in `capi.cc`
2. **"undefined: bindings.FunctionName"** - Add stub implementation to `bindings_stub.go`
3. **Type mismatch errors** - Verify C types match between header and implementation

### Test Failures

1. **Timeout** - Increase context timeout or check for deadlocks
2. **Output mismatch** - Verify the C++ implementation behavior matches test expectations
3. **Memory errors** - Check that memory conversion functions are used correctly

## Additional Resources

- cb-mpc C++ documentation: See `cb-mpc/src/cbmpc/protocol/` headers
- CGO documentation: https://pkg.go.dev/cmd/cgo
- Go testing: https://pkg.go.dev/testing
