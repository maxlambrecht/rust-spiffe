# Rust SPIFFE Libraries

[![CI](https://github.com/maxlambrecht/rust-spiffe/actions/workflows/ci-main.yml/badge.svg?branch=main)](https://github.com/maxlambrecht/rust-spiffe/actions/workflows/ci.yml?query=branch%3Amain)
[![Coverage](https://coveralls.io/repos/github/maxlambrecht/rust-spiffe/badge.svg?branch=main)](https://coveralls.io/github/maxlambrecht/rust-spiffe?branch=main)
[![Crates.io](https://img.shields.io/crates/v/spiffe.svg)](https://crates.io/crates/spiffe)
[![Crates.io](https://img.shields.io/crates/v/spiffe-rustls.svg)](https://crates.io/crates/spiffe-rustls)
[![Crates.io](https://img.shields.io/crates/v/spiffe-rustls-tokio.svg)](https://crates.io/crates/spiffe-rustls-tokio)
[![Crates.io](https://img.shields.io/crates/v/spire-api.svg)](https://crates.io/crates/spire-api)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/11801/badge)](https://www.bestpractices.dev/projects/11801)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Safety](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance)

A collection of Rust libraries for working with **SPIFFE** and **SPIRE**, covering identity
representation, SPIRE-specific APIs, and TLS/mTLS integration.

---

## Project Scope and Goals

These crates aim to provide **standards-compliant, well-engineered building blocks** for integrating
SPIFFE and SPIRE into Rust applications.

The project focuses on:

- Correctness and clarity of APIs
- Alignment with SPIFFE specifications
- Conservative security-oriented design
- Explicit dependency and feature management

This repository does **not** claim formal security audits or guaranteed production fitness. Users
should evaluate suitability based on their own requirements and threat models.

---

## Why Use These Crates?

These crates emphasize **sound engineering practices** and **security-conscious design**:

- ✅ **Zero unsafe code** — enforced via `#![deny(unsafe_code)]`
- ✅ **Comprehensive testing** — unit and integration tests, including CI runs against SPIRE deployments
- ✅ **Feature-gated dependencies** — no default features; enable only what you need
- ✅ **Standards aligned** — follows the SPIFFE specifications
- ✅ **Maintained** — regular updates with a documented MSRV policy (Rust 1.85+)

---

## Crates

### [`spiffe`](./spiffe)

Standards-aligned SPIFFE primitives and a client for the **SPIFFE Workload API**.

**Use this crate if you need:**

- X.509 and JWT SVID handling
- Trust bundle management
- Streaming identity updates
- Strongly typed SPIFFE identifiers and trust domains

See the [spiffe README](./spiffe/README.md) for usage and API documentation.

---

### [`spire-api`](./spire-api)

Rust bindings for **SPIRE-specific gRPC APIs** that are not part of the SPIFFE standards.

**Use this crate if you need:**

- The SPIRE Delegated Identity API
- Direct interaction with SPIRE agent or server extensions

See the [spire-api README](./spire-api/README.md) for details.

---

### [`spiffe-rustls`](./spiffe-rustls)

Integration between SPIFFE identities and [`rustls`](https://crates.io/crates/rustls).

**Use this crate if you need:**

- Mutual TLS (mTLS) using SPIFFE identities
- Automatic handling of SVID and trust bundle rotation
- Connection-level authorization based on SPIFFE IDs

See the [spiffe-rustls README](./spiffe-rustls/README.md) for configuration and examples.

---

### [`spiffe-rustls-tokio`](./spiffe-rustls-tokio)

Tokio-native accept/connect helpers for `spiffe-rustls` configurations.

**Use this crate if you need:**

- Async TLS connections with Tokio
- Automatic peer SPIFFE ID extraction from TLS connections
- Convenient `TlsAcceptor` and `TlsConnector` APIs

See the [spiffe-rustls-tokio README](./spiffe-rustls-tokio/README.md) for usage and examples.

---

## Choosing a Crate

- **SPIFFE identities or Workload API access** → `spiffe`
- **SPIRE gRPC APIs** → `spire-api`
- **mTLS with SPIFFE over rustls** → `spiffe-rustls`
- **Tokio async TLS with SPIFFE** → `spiffe-rustls-tokio`

---

## Engineering Practices

The project follows established Rust ecosystem practices:

- **Safety**: No `unsafe` code
- **Testing**: Unit and integration test coverage
- **Documentation**: Public API documentation with examples on [docs.rs](https://docs.rs)
- **CI**: Automated testing across feature combinations and MSRV
- **Error handling**: Explicit, strongly typed errors using `thiserror`
- **Observability**: Optional integration with `log` and `tracing`

---

## Getting Started

Each crate is independently versioned and documented. Refer to the corresponding crate README for
installation instructions, examples, and API documentation.

---

## Contributing

Contributions are welcome. Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/maxlambrecht/rust-spiffe.git
cd rust-spiffe

# Quick check (formatting + linting + build, no tests)
make check

# Full test suite (formatting + linting + build + tests)
make all

# Run full CI checks locally (includes MSRV verification)
make ci

# Run integration tests (requires SPIRE setup)
make integration-tests
```

See `make help` for all available targets.

### Reporting Issues

Please file bugs and feature requests via
[GitHub Issues](https://github.com/maxlambrecht/rust-spiffe/issues).

### Security

For security-related issues, please follow the disclosure process described in
[SECURITY.md](SECURITY.md).

---

## License

Licensed under the Apache License, Version 2.0.
See [LICENSE](./LICENSE) for details.
