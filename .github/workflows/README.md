# CI/CD Workflows

This directory contains GitHub Actions workflows for automated testing, linting, and security checks.

## Workflows

### 🧪 test.yml - Core Testing
**Triggers**: Push to main/master, Pull Requests

**What it does**:
- Builds the C++ library with caching for performance
- Runs all Go tests including ECDSA 2PC and malicious party tests
- Verifies examples compile correctly
- Checks Go formatting and runs `go vet`
- Ensures CGO isolation (only `internal/cgo` imports "C")
- Validates Go modules

**Key Features**:
- ✅ Submodule support with recursive checkout
- ✅ C++ build caching for faster runs
- ✅ Comprehensive test coverage including security tests
- ✅ Architecture validation

### 🔍 lint.yml - Code Quality
**Triggers**: Push to main/master, Pull Requests

**What it does**:
- Runs golangci-lint with comprehensive linter configuration
- Checks code style, complexity, and potential issues
- CGO-aware linting with proper environment setup

**Configuration**: `.golangci.yml`

### 🔒 security.yml - Security Analysis
**Triggers**: Push to main/master, Pull Requests

**What it does**:
- Runs `gosec` security scanner for Go code
- Checks for known vulnerabilities with Nancy
- Scans for hardcoded secrets with TruffleHog
- Runs race condition detection
- Validates no hardcoded certificates in production code

**Security Checks**:
- ✅ Vulnerability scanning
- ✅ Secret detection
- ✅ Race condition analysis
- ✅ Memory safety validation

## Configuration Files

### .golangci.yml
Comprehensive linting configuration with:
- CGO-specific exclusions
- Security-focused rules
- Code quality checks
- Test-specific allowances

### .github/dependabot.yml
Automated dependency updates for:
- Go modules (weekly)
- GitHub Actions (weekly)
- Git submodules (weekly)

## Pull Request Guidelines

All PRs automatically trigger:
1. **Core Tests** - Full test suite including malicious party scenarios
2. **Linting** - Code quality and style checks
3. **Security Scan** - Vulnerability and secret detection
4. **Build Verification** - Ensure examples compile

### Required Checks
✅ All tests pass
✅ No linting errors
✅ No security vulnerabilities
✅ CGO properly isolated
✅ Examples compile successfully

### Performance Optimizations
- **C++ Build Caching**: Dramatically reduces CI time by caching compiled C++ library
- **Parallel Jobs**: Security, linting, and testing run concurrently
- **Smart Triggers**: Only runs on relevant branches and PRs

## Local Development

To run the same checks locally:

```bash
# Run all tests
make test

# Check formatting
gofmt -s -l .

# Run linting (install golangci-lint first)
golangci-lint run

# Check CGO isolation
grep -r 'import "C"' --include="*.go" . | grep -v "internal/cgo/" | grep -v "cb-mpc/" && echo "❌ CGO not isolated" || echo "✅ CGO properly isolated"

# Security scan (install gosec first)
gosec ./...
```

## Troubleshooting

### Common Issues

1. **C++ Build Fails**
   - Check submodule is properly initialized
   - Ensure build dependencies are installed
   - Verify CMake and ninja are available

2. **CGO Tests Fail**
   - Verify `CGO_ENABLED=1`
   - Check C++ library is built and linked correctly
   - Ensure proper environment variables are set

3. **Linting Errors**
   - Run `gofmt -s -w .` to fix formatting
   - Address specific linter warnings in `.golangci.yml`
   - Check CGO code exclusions are working

### Cache Issues

If C++ build cache becomes stale:
- Update the cache key in `test.yml`
- Or manually clear the cache in GitHub Actions settings

## Security Considerations

- ✅ **No Secrets in CI**: All workflows use only public tokens
- ✅ **Minimal Permissions**: Workflows use least-privilege access
- ✅ **Dependency Scanning**: Automated vulnerability detection
- ✅ **Secret Scanning**: Prevents accidental secret commits
- ✅ **Race Detection**: Memory safety validation for CGO code