# Contributing to cb-mpc-go

We value community contributions and aim to keep the review loop fast. If something feels unclear or slows you down, open an issue so we can fix the process.

## Quick Start Checklist

1. Use Go 1.22 (CI pins to Go 1.22.x). The helper scripts bootstrap toolchains automatically, or you can install Go yourself.
2. Make sure Git LFS is installed before cloning or updating submodules (`brew install git-lfs && git lfs install`).
3. Build the native dependencies once with `make build-cbmpc`.
4. Keep changes focussed and small; large rewrites land faster when split into reviewable pieces.

## Developing Locally

- Formatting: run `go fmt ./...` or simply execute `make lint-fix` to auto-format and apply supported fixes.
- Linting: `make lint` (wraps `golangci-lint` v1.64.8 pinned in the toolchain).
- Testing: `make test` (executes all Go tests; depends on `make build-cbmpc`).
- Dev container: export `CBMPC_USE_DOCKER=1` to run any target in the Linux CI image.

## Pull Request Requirements

Every PR should:

- Reference a GitHub issue when the change is user-visible or behavioural (feel free to file one if it does not exist yet).
- Include tests or explain why testing is not applicable.
- Pass `make lint`, `make vuln`, `make sec`, and `make test` locally; CI will block merges on these checks.
- Leave the workspace clean (`go mod tidy` should produce no diff).

### Fast-Path Reviews

To help maintainers respond quickly:

- Keep commits logically grouped and describe user-facing effects in the commit message body.
- Call out any follow-up work that is intentionally left for later.
- Use draft PRs for early feedback; converting to “Ready for review” triggers maintainer triage.

## Security and Responsible Disclosure

Never disclose security issues in public issues or pull requests. Email the security contact listed in `SECURITY.md` instead.

Thank you for helping make cb-mpc-go better!
