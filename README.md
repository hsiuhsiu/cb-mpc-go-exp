# cb-mpc-go

A production-focused Go wrapper around [Coinbase's cb-mpc](https://github.com/coinbase/cb-mpc) multi-party computation (MPC) library. The goal of this repository is to surface a safe, ergonomic, and well-structured Go API while building directly from the C++ source tree. All tooling runs natively by default, and you can opt into a reproducible Docker environment by exporting `CBMPC_USE_DOCKER=1` (the same mode used by CI).

## Repository layout

- `third_party/cb-mpc`: git submodule tracking the upstream C++ library.
- `pkg/cbmpc`: public Go API surface; will grow as bindings are implemented.
- `cmd/cbmpc-go`: placeholder command-line entry point useful for manual smoke testing during development.
- `docker/`: container images that match the CI environment for linting and testing.
- `.github/workflows/`: GitHub Actions pipelines for linting and testing pull requests.

## Getting started

1. Clone the repository and initialize submodules:

   ```bash
   git clone git@github.com:coinbase/cb-mpc-go.git
   cd cb-mpc-go
   git submodule update --init --recursive
   ```

2. Build the cb-mpc C++ static library from source without installing it system-wide:

   ```bash
   make build-cbmpc
   ```

   The helper target downloads a local static OpenSSL 3.2.0 build into `build/openssl`, patches the upstream CMake scripts to respect that location, and emits `libcbmpc.a` under `build/cb-mpc`.

3. Run the (currently minimal) Go test suite (the target depends on `make build-cbmpc` to ensure the native library is present):

   ```bash
   make test
   ```

   On a clean macOS install the helper script automatically downloads Go 1.22.5 into `build/go`. Set `CBMPC_USE_DOCKER=1` if you prefer to run the tests inside the dev container.

4. Run Go linters:

   ```bash
   make lint
   ```

   A matching `golangci-lint` v1.58.1 binary is installed into `build/bin` on demand, or you can execute the lint target inside Docker by exporting `CBMPC_USE_DOCKER=1`.

## Development workflow

- `make lint-fix` formats and auto-fixes lint findings when supported by `golangci-lint`.
- `make clean` removes all generated build artefacts, including the local cb-mpc build directory.
- Tool shims bootstrap pinned Go and `golangci-lint` toolchains automatically; export `CBMPC_USE_DOCKER=1` to run the same workflow inside the dev container.
- The Dockerfiles under `docker/` mirror the tooling used in CI, allowing local validation via `docker build -f docker/dev.Dockerfile .`.

## Continuous integration

GitHub Actions workflows invoke the same Make targets (`make lint`, `make test`) on every pull request with `CBMPC_USE_DOCKER=1`, so CI runs inside the dev container while local development can stay native.

## Next steps

- Implement cgo bindings that link against `build/cb-mpc`
- Model higher-level Go APIs that expose safe MPC workflows
- Expand testing (unit and integration) around the bindings once available

