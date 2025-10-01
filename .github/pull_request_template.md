## Description

Brief description of the changes in this PR.

## Type of Change

- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update
- [ ] Security improvement
- [ ] Performance improvement

## Testing

- [ ] I have added tests that prove my fix is effective or that my feature works
- [ ] New and existing unit tests pass locally with my changes
- [ ] I have tested the changes with the provided examples

## Security Checklist

- [ ] No hardcoded secrets or credentials
- [ ] Proper input validation
- [ ] Memory management is correct (especially for CGO code)
- [ ] No new security vulnerabilities introduced

## CGO Changes (if applicable)

- [ ] CGO code is isolated to `internal/cgo` package only
- [ ] Proper memory management (malloc/free pairing)
- [ ] No Go pointers passed to C code
- [ ] Thread safety considerations documented

## Documentation

- [ ] I have updated relevant documentation
- [ ] Code is properly commented, especially complex logic
- [ ] Examples are updated if needed

## Breaking Changes

If this is a breaking change, please describe the impact and migration path for existing users:

## Additional Notes

Any additional information that reviewers should know.