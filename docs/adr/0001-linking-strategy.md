# ADR-0001: Linking strategy

## Status

Accepted

## Context

The Go wrapper must link against the upstream cb-mpc static library and its
OpenSSL dependency. The repository already contains helper targets that build
both artefacts under `build/` and never touch system-wide installations. We
need a documented policy so downstream contributors understand how binaries are
assembled and what licensing considerations exist.

## Decision

- We statically link against the cb-mpc static library produced by
  `make build-cbmpc`, which copies the upstream `libcbmpc.a` into
  `build/cb-mpc-*`.
- OpenSSL is built from source by `make openssl` and installed under
  `build/openssl-*`. We do **not** link against the system OpenSSL by default to
  avoid ABI drift and to keep provenance clear.
- Both the cb-mpc and OpenSSL builds run inside the repo-controlled build
  directories so we can track provenance. The top-level `LICENSE` and
  third_party submodule already contain appropriate license text; this ADR makes
  explicit that the produced binaries inherit those licences.
- CI and developers must rely on the repo-managed builds rather than system
  packages. Future tooling can add trust checks (hashes, SLSA attestations) but
  the default remains “build everything under `build/`”.

## Consequences

- Keeping all artefacts under `build/` standardises the layout across macOS,
  Linux, and Docker builds, and the ADR gives us a single place to evolve the
  policy.
- Packaging downstream binaries requires shipping the statically built
  OpenSSL/cb-mpc libraries; dynamic linkage to the system remains unsupported
  unless a follow-on ADR revisits this decision.
