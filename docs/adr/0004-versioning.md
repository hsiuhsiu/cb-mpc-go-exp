# ADR-0004: Versioning

## Status

Accepted

## Context

The repository is new and the API surface is still evolving. We need a version
policy that communicates stability to downstreams and defines where public
symbols live.

## Decision

- The module follows semantic versioning, starting at v0.x until the public API
  reaches stability. Breaking changes remain allowed but require release notes.
- Only the `pkg/cbmpc` package is considered public; anything under
  `internal/` or other paths may change without notice.
- The repository will tag releases (e.g., `v0.1.0`) once meaningful subsets of
  functionality land. Pre-release interoperability with the upstream C++ code
  happens under v0.x.
- Once the API is ready for 1.0 we will issue ADR-XXXX revisiting this policy.

## Consequences

- Downstreams know that importing `pkg/cbmpc` is the supported path and can pin
  minor versions under v0.
- Internal helpers can evolve rapidly without deprecation windows.
