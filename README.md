# SPIFFE Crates

[![CI](https://github.com/maxlambrecht/rust-spiffe/actions/workflows/ci-main.yml/badge.svg?branch=main)](https://github.com/maxlambrecht/rust-spiffe/actions/workflows/ci.yml?query=branch%3Amain)
[![Coverage](https://coveralls.io/repos/github/maxlambrecht/rust-spiffe/badge.svg?branch=main)](https://coveralls.io/github/maxlambrecht/rust-spiffe?branch=main)
[![Crates.io](https://img.shields.io/crates/v/spiffe.svg)](https://crates.io/crates/spiffe)
[![Crates.io](https://img.shields.io/crates/v/spiffe-rustls.svg)](https://crates.io/crates/spiffe-rustls)
[![Crates.io](https://img.shields.io/crates/v/spiffe-rustls-tokio.svg)](https://crates.io/crates/spiffe-rustls-tokio)
[![Crates.io](https://img.shields.io/crates/v/spire-api.svg)](https://crates.io/crates/spire-api)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/11801/badge)](https://www.bestpractices.dev/projects/11801)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Safety](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance)

A collection of crates for SPIFFE workload identity, Workload API clients, SPIRE-specific APIs, and TLS integration.

---

## Project Scope and Goals

These crates provide standards-compliant building blocks for integrating
SPIFFE and SPIRE into Rust applications.

The project focuses on:

- Correctness and clarity of APIs
- Alignment with SPIFFE specifications
- Conservative security-oriented design
- Explicit dependency and feature management

This repository does **not** claim formal security audits or guaranteed production fitness. Users
should evaluate suitability based on their own requirements and threat models.

---

## Available Crates

These crates can be used independently or layered together, depending on the level of
abstraction required.

### [`spiffe`](./spiffe)

Standards-aligned SPIFFE identity primitives and clients for the **SPIFFE Workload API**.

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
- TLS-level peer authorization based on SPIFFE IDs

See the [spiffe-rustls README](./spiffe-rustls/README.md) for configuration and examples.

---

### [`spiffe-rustls-tokio`](./spiffe-rustls-tokio)

Tokio-native async accept/connect helpers for `spiffe-rustls` configurations.

**Use this crate if you need:**

- Async TLS connections with Tokio
- Automatic peer SPIFFE ID extraction from TLS connections
- `TlsAcceptor` and `TlsConnector` APIs

See the [spiffe-rustls-tokio README](./spiffe-rustls-tokio/README.md) for usage and examples.

---

## Choosing a Crate

Most users will interact with one or more of the following:

- **SPIFFE identities or Workload API access** → `spiffe`
- **SPIRE gRPC APIs** → `spire-api`
- **mTLS with SPIFFE over rustls** → `spiffe-rustls`
- **Tokio async TLS with SPIFFE** → `spiffe-rustls-tokio`

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
