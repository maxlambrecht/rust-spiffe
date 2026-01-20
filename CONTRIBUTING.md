# Contributing to Rust SPIFFE Libraries

Thank you for your interest in contributing to the Rust SPIFFE libraries!

This project values clear APIs, disciplined changes, and a low-noise contribution process.

---

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

# Quick check (formatting + linting + build, no tests)
make check

# Full check (formatting + linting + build + tests)
make all

# Run full CI checks locally (includes MSRV verification)
make ci

# Run integration tests (requires SPIRE setup)
make integration-tests
```

---

## Code Style

* Follow standard Rust formatting (`make fmt` or `cargo fmt`)
* Run `make lint` to check for clippy warnings (or `cargo clippy` directly)
* Ensure all public APIs are documented (`#![deny(missing_docs)]`)
* No `unsafe` code blocks (enforced by `#![deny(unsafe_code)]`)

---

## Testing

### Unit Tests

```bash
# Run tests on all crates (default features only)
make test

# Test a specific crate (full feature matrix)
make spiffe
make spiffe-rustls
make spire-api
```

### Integration Tests

Integration tests require a running SPIRE agent. See
`.github/workflows/scripts/run-spire.sh` for setup instructions.

```bash
# Run all integration tests
make integration-tests
```

### Fuzz Testing

The project includes fuzz targets for validating SPIFFE ID and TrustDomain
parsing logic, located under `spiffe/fuzz/`.

Fuzzing is used to harden parsing against malformed or adversarial inputs and
to enforce core invariants such as round-trip stability and API consistency.

Running fuzz tests locally requires `cargo-fuzz` and a nightly Rust toolchain.

```bash
# Install cargo-fuzz if needed
cargo +nightly install cargo-fuzz --locked

# Run all fuzz targets
make fuzz
```

Fuzz tests are not required for every pull request, but contributors touching
parsing, validation, or security-sensitive code are encouraged to run them
locally.

---

## Pull Request Process

1. **Fork and branch**: Create a feature branch from `main`
2. **Make changes**: Follow code style guidelines
3. **Test**: Ensure all tests pass (`make all` or `make ci` for full CI checks)
4. **Document**: Update README/docs if needed
5. **Submit**: Open a PR with a clear description

Reviews are done on a best-effort basis. Please allow time for feedback.

### PR Checklist

* [ ] Code follows style guidelines (`make fmt-check`, `make lint`)
* [ ] All tests pass (`make all`)
* [ ] MSRV compatibility verified (`make msrv` or `make ci`)
* [ ] Integration tests pass (if applicable)
* [ ] Documentation updated (if needed)
* [ ] CHANGELOG updated (if applicable)

---

## Contribution Conventions

This project follows **Conventional Commits** and **Conventional Pull Requests**.

### Pull Requests

* PR titles must follow the format:
  `<type>(<scope>): <description>`
* Example:
  `feat(spiffe): add JwtSource API`
* PRs are squash-merged; the PR title becomes the commit message.

### Branches

* Branches are short-lived and named using:
  `<type>/<short-description>`
* Examples:

    * `feat/jwt-source`
    * `fix/bundle-rotation`
    * `chore/release-0.11.0`
* Branches are deleted after merge.

### Commits

* Commits must follow Conventional Commits.
* Release commits use the format:
  `chore(release): <crate> <version>`

---

## CI and Policy Checks

Pull requests are checked using automated CI, including:

* Formatting and linting
* Unit and integration tests
* Dependency vulnerability scanning (`cargo-audit`)
* Dependency, license, and source policy checks (`cargo-deny`)

New dependencies must comply with the existing policy defined in `deny.toml`.

---

## Feature Development

### Adding New Features

* Keep features opt-in (no default features)
* Gate functionality behind feature flags in `Cargo.toml`
* Update the feature matrix in crate documentation
* Add tests for new functionality

---

## Questions?

* Open an issue for bugs or feature requests
* Check existing issues and PRs before creating new ones
* Be respectful and constructive in discussions
