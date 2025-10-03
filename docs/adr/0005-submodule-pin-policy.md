# ADR-0005: Submodule pin policy

## Status

Accepted

## Context

The Go wrapper depends on the upstream C++ repository via the `cb-mpc` Git submodule.
Allowing the submodule to drift onto mutable branches
creates non-deterministic builds and makes provenance audits difficult. We want
clear guidance on how we pin and update the submodule.

## Decision

- The submodule must always point at an immutable commit SHA. We never pin to a
  branch, tag, or floating reference.
- Bumps to the submodule land only after the upstream repository publishes
  release notes or our scheduled CI runs (weekly) succeed on the candidate
  commit.
- Every bump includes notes in the pull request describing the upstream change
  set and any resulting adjustments to the Go wrapper.
- CI verifies that the submodule is clean and matches the pinned SHA.

## Consequences

- Developers know not to run `git submodule update --remote` or similar branch
  tracking commands without an explicit review cycle.
- When issues arise we can correlate binaries with the exact upstream commit and
  reproduce the build reliably.
