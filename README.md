# cb-mpc-go

A production-focused Go wrapper around [Coinbase's cb-mpc](https://github.com/coinbase/cb-mpc) multi-party computation (MPC) library. The goal of this repository is to surface a safe, ergonomic, and well-structured Go API while building directly from the C++ source tree. All tooling runs natively by default, and you can opt into a reproducible Docker environment by exporting `CBMPC_USE_DOCKER=1` (the same mode used by CI).

## Repository layout

- `third_party/cb-mpc`: git submodule tracking the upstream C++ library.
- `pkg/cbmpc`: public Go API surface; will grow as bindings are implemented.
- `cmd/cbmpc-go`: placeholder command-line entry point useful for manual smoke testing during development.
- `docker/`: container images that match the CI environment for linting and testing.
- `.github/workflows/`: GitHub Actions pipelines for linting and testing pull requests.

## Getting started

1. Install prerequisites:

   ```bash
   brew install git-lfs            # or use your distro package manager
   git lfs install
   ```

   The upstream cb-mpc submodule stores several assets in Git LFS; without these commands `git submodule update` will emit warnings and leave large binaries out of sync.

2. Clone the repository and initialize submodules:

   ```bash
   git clone git@github.com:coinbase/cb-mpc-go.git
   cd cb-mpc-go
   git submodule update --init --recursive
   ```

3. Build the cb-mpc C++ static library from source without installing it system-wide:

   ```bash
   make build-cbmpc
   ```

   The examples below run natively. If you prefer the Linux dev container, prefix commands with `CBMPC_USE_DOCKER=1` (Docker must be available and running).

   Native builds write artefacts under `build/openssl-host` and `build/cb-mpc-host`. When running with `CBMPC_USE_DOCKER=1`, the helper scripts isolate the container builds under `build/openssl-docker` and `build/cb-mpc-docker` to avoid CMake cache conflicts.

4. Run the (currently minimal) Go test suite (the target depends on `make build-cbmpc` to ensure the native library is present):

   ```bash
   make test
   ```

   On a clean macOS install the helper script automatically downloads Go 1.23.12 into `build/go-host`. Set `CBMPC_USE_DOCKER=1` if you prefer to run the tests inside the dev container, which will keep its own toolchain under `build/go-docker`.

5. Run Go linters:

   ```bash
   make lint
   ```

   A matching `golangci-lint` v1.64.8 binary is installed into `build/bin-host` (or `build/bin-docker` in container mode) on demand.

## Development workflow

- `make bootstrap` runs Git LFS setup, syncs submodules, and performs the initial cb-mpc build.
- `make lint-fix` formats and auto-fixes lint findings when supported by `golangci-lint`.
- `make vuln` executes `govulncheck ./...` with the pinned toolchain, while `make sec` wraps `gosec` with exclusions for generated cgo shims.
- `make tidy-check` ensures `go.mod` and `go.sum` stay clean by running `go mod tidy` and failing on diffs.
- `make clean` removes all generated build artefacts, including the local cb-mpc build directory.
- Tool shims bootstrap pinned Go and `golangci-lint` toolchains automatically and keep separate caches per environment flavour (`*-host` vs `*-docker`) so you can switch between native macOS and Linux container runs without manual cleanup. Export `CBMPC_USE_DOCKER=1` to run the same workflow inside the dev container.
- The Dockerfiles under `docker/` mirror the tooling used in CI, allowing local validation via `docker build -f docker/dev.Dockerfile .`.

## Continuous integration

GitHub Actions workflows invoke the same Make targets (`make lint`, `make vuln`, `make sec`, `make test`) on every pull request with `CBMPC_USE_DOCKER=1`, so CI runs inside the dev container while local development can stay native.

## Next steps

- Implement cgo bindings that link against `build/cb-mpc`
- Model higher-level Go APIs that expose safe MPC workflows
- Expand testing (unit and integration) around the bindings once available

