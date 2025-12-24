# Rust SPIFFE Libraries

[![Build](https://github.com/maxlambrecht/rust-spiffe/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/maxlambrecht/rust-spiffe/actions/workflows/ci.yml?query=branch%3Amain)
[![Coverage](https://coveralls.io/repos/github/maxlambrecht/rust-spiffe/badge.svg?branch=main)](https://coveralls.io/github/maxlambrecht/rust-spiffe?branch=main)

A collection of Rust libraries for working with **SPIFFE** and **SPIRE**, covering identity
representation, SPIRE-specific APIs, and TLS/mTLS integration.

---

## Crates

### [`spiffe`](./spiffe)

Standards-compliant SPIFFE primitives and a client for the **SPIFFE Workload API**.

**Use this crate if you need:**
- X.509 and JWT SVIDs
- Trust bundles
- Streaming identity updates
- Strongly typed SPIFFE identifiers and trust domains

See the [spiffe README](./spiffe/README.md) for usage and API details.

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
- Mutual TLS (mTLS) based on SPIFFE identities
- Automatic handling of SVID and bundle rotation
- Connection-level authorization using SPIFFE IDs

See the [spiffe-rustls README](./spiffe-rustls/README.md) for configuration and examples.

---

## Choosing a crate

- **SPIFFE identities or Workload API access** → `spiffe`
- **SPIRE gRPC APIs** → `spire-api`
- **mTLS with SPIFFE over rustls** → `spiffe-rustls`

---

## Getting started

Each crate is independently versioned and documented. Refer to the corresponding crate README for
installation instructions, examples, and API documentation.

---

## License

Licensed under the Apache License, Version 2.0.  
See [LICENSE](./LICENSE) for details.
