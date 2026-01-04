# Contributing to Rust SPIFFE Libraries

Thank you for your interest in contributing to the Rust SPIFFE libraries!

## Development Setup

### Prerequisites

- Rust 1.85 or later (see `rust-version` in `Cargo.toml`)
- `make` (for running the test suite)
- SPIRE agent (for integration tests)

### Getting Started

```bash
# Clone the repository
git clone https://github.com/maxlambrecht/rust-spiffe.git
cd rust-spiffe

# Run all checks (formatting, linting, building, testing)
make all

# Run integration tests (requires SPIRE setup)
make integration-tests
```

## Code Style

- Follow standard Rust formatting (`cargo fmt`)
- Run `cargo clippy` and address warnings
- Ensure all public APIs are documented (`#![deny(missing_docs)]`)
- No `unsafe` code blocks (enforced by `#![deny(unsafe_code)]`)

## Testing

### Unit Tests

```bash
# Test a specific crate
make spiffe
make spiffe-rustls
make spire-api
```

### Integration Tests

Integration tests require a running SPIRE agent. See `.github/workflows/scripts/run-spire.sh` for setup instructions.

```bash
# Run all integration tests
make integration-tests
```

## Pull Request Process

1. **Fork and branch**: Create a feature branch from `main`
2. **Make changes**: Follow code style guidelines
3. **Test**: Ensure all tests pass (`make all`)
4. **Document**: Update README/docs if needed
5. **Submit**: Open a PR with a clear description

Reviews are done on a best-effort basis. Please allow time for feedback.


### PR Checklist

- [ ] Code follows style guidelines
- [ ] All tests pass (`make all`)
- [ ] Integration tests pass (if applicable)
- [ ] Documentation updated (if needed)
- [ ] CHANGELOG updated (if applicable)

## CI and Policy Checks

Pull requests are checked using automated CI, including:

- Formatting and linting
- Unit and integration tests
- Dependency vulnerability scanning (`cargo-audit`)
- Dependency, license, and source policy checks (`cargo-deny`)

New dependencies must comply with the existing policy defined in `deny.toml`.

## Feature Development

### Adding New Features

- Keep features opt-in (no default features)
- Gate behind feature flags in `Cargo.toml`
- Update feature matrix in crate documentation
- Add tests for new functionality

## Questions?

- Open an issue for bugs or feature requests
- Check existing issues and PRs before creating new ones
- Be respectful and constructive in discussions

