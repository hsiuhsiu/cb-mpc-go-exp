# ADR-0002: Memory ownership & zeroization

## Status

Accepted

## Context

The native cb-mpc library manipulates sensitive material (private keys,
nonces). The Go wrapper must define clear rules for who allocates and frees
memory when crossing the boundary, how buffers are protected from garbage
collection, and where zeroization happens. Without a documented strategy the
implementation risks double-frees, leaks, or secrets lingering in memory.

## Decision

- **Ownership boundary:** Go code owns the lifetime of all buffers passed into
  cgo. The bindings will allocate Go-managed `[]byte` or fixed-size arrays and
  copy data into C memory when required. The C side may read from or write to
  buffers but must not free them; the Go bindings remain responsible.
- **Allocation strategy:** For fixed-size secrets (e.g., scalars, seeds) we
  allocate `[32]byte` (or similar) buffers in Go to avoid heap reallocations.
  Slices used for variable-length payloads are kept alive with
  `runtime.KeepAlive` immediately after the C call.
- **Constant-time comparisons:** All secret comparisons in Go must use helpers from `crypto/subtle` (enforced via gosec + AST tests under `pkg/cbmpc/internalcheck`).
- **Zeroization:** Sensitive buffers are zeroized on both sides of the
  boundary. In Go, `pkg/cbmpc/zeroize.go` exposes helpers that zero slices and
  strings before release. In cgo, helper wrappers call `OPENSSL_cleanse` or
  equivalent routines before returning.
- **Error paths:** If a cgo call fails, the Go wrapper zeroizes any partially
  written buffers before returning. handles returned from cgo must be closed via
  `Library.Close`, which will finalize and zero secrets.
- **Testing:** We will add unit tests (Go) and integration tests (cgo) to ensure
  zeroization happens at the documented points once bindings arrive.

## Consequences

- The bindings are explicit about ownership so future contributors know where
  to add `free` calls. Keeping allocations in Go reduces surprise for garbage
  collector behaviour.
- Zeroization helpers introduce additional copy costs, but the deterministic
  behaviour is preferable for cryptographic material. Performance tuning can
  revisit the strategy if proven necessary.
