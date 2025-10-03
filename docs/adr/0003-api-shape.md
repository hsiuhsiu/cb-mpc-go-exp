# ADR-0003: API shape

## Status

Accepted

## Context

The Go API should expose a composable surface that downstream services can rely
on. We want to agree on naming, error semantics, and the role of context before
implementing the bindings, to avoid disruptive rework later.

## Decision

- The top-level API centres around three types:
  - `Library`: manages the process-wide cb-mpc instance and owns native
    resources (already stubbed in `pkg/cbmpc/lib.go`).
  - `KeySet`: wraps long-lived public/private key material. TODO: scaffolding
    arrives in follow-on tasks but the ADR records the intent.
  - `Signer`: offers stateless signing operations parameterized by a `KeySet`.
- Every exported method that may block or perform native work accepts a
  `context.Context` as the first parameter. This allows cancellation and aligns
  with other Coinbase Go APIs.
- The package uses sentinel errors (`ErrCGONotEnabled`, `ErrNotBuilt`, etc.) and
  `errors.Is` for classification; additional error values (e.g.
  `ErrInvalidKey`, `ErrSigningFailed`) will follow the same pattern.
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
