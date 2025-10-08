# ADR-0003: API shape

## Status

Accepted

## Context

The Go API should expose a composable surface that downstream services can rely
on. We want to agree on naming, error semantics, and the role of context before
implementing the bindings, to avoid disruptive rework later.

## Decision

- The API is organized around job-based MPC protocols:
  - `Job2P` and `JobMP`: manage two-party and multi-party MPC sessions respectively,
    handling transport and native resource lifecycle.
  - Protocol functions (e.g., `AgreeRandom`, `MultiAgreeRandom`): stateless operations
    that accept a job and perform MPC computations.
  - `Transport` interface: allows users to provide custom network implementations.
  - Future types (`KeySet`, `Signer`): will follow similar patterns for key management
    and signing operations.
- Every exported method that may block or perform native work accepts a
  `context.Context` as the first parameter. This allows cancellation and aligns
  with other Coinbase Go APIs.
- The package uses standard Go errors with descriptive messages; additional sentinel
  errors (e.g., `ErrInvalidBits`, `ErrBadPeers`) are defined as needed for specific
  error conditions.
- Cryptographically sensitive comparisons use constant-time helpers from
  `crypto/subtle`.
- Logging flows use a small wrapper around `log/slog`; secrets must be redacted via helper functions (no raw `%x`).
- No symbols outside `pkg/cbmpc` are exported; internal helpers live in
  `internal/bindings` and future subpackages.

## Consequences

- The ADR sets expectations for future scaffolding (`KeySet`, `Signer`) so the
  team can review designs against this baseline.
- Using contexts and sentinel errors introduces boilerplate but provides
  predictable ergonomics for downstream users.
