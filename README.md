# Rust SPIFFE Libraries

[![Build](https://github.com/maxlambrecht/rust-spiffe/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/maxlambrecht/rust-spiffe/actions/workflows/ci.yml?query=branch%3Amain)
[![Coverage](https://coveralls.io/repos/github/maxlambrecht/rust-spiffe/badge.svg?branch=main)](https://coveralls.io/github/maxlambrecht/rust-spiffe?branch=main)

[![Docs: spiffe](https://docs.rs/spiffe/badge.svg)](https://docs.rs/spiffe/)
[![Docs: spire-api](https://docs.rs/spire-api/badge.svg)](https://docs.rs/spire-api/)
[![Docs: spiffe-rustls](https://docs.rs/spiffe-rustls/badge.svg)](https://docs.rs/spiffe-rustls/)

This repository contains a set of Rust libraries focused on supporting **SPIFFE** and **SPIRE**
functionality across different layers of the stack.

The workspace is organized as multiple crates, each targeting a specific concern: standards-compliant
identity types, SPIRE-specific APIs, and TLS/mTLS integration.

---

## Crates Overview

### [spiffe](./spiffe)

The `spiffe` crate provides a Rust implementation of the
[SPIFFE Workload API](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md).

It supports:

* Fetching X.509 and JWT SVIDs
* Fetching trust bundles
* Watching and streaming identity updates via the Workload API

All types and behaviors are compliant with the official
[SPIFFE standards](https://github.com/spiffe/spiffe/tree/main/standards).
General information about SPIFFE is available at [spiffe.io](https://spiffe.io/).

* See the [spiffe README](./spiffe/README.md) for usage and API details.

---

### [spire-api](./spire-api)

The `spire-api` crate provides Rust bindings for **SPIRE-specific gRPC APIs** that are not part of the
core SPIFFE standards.

This includes:

* The SPIRE Delegated Identity API
* Other SPIRE agent and server extensions

This crate is intended for applications or services that need to interact directly with SPIRE’s
gRPC APIs beyond the Workload API.

* See the [spire-api README](./spire-api/README.md) for details.

---

### [spiffe-rustls](./spiffe-rustls)

The `spiffe-rustls` crate integrates SPIFFE identity with
[`rustls`](https://crates.io/crates/rustls) using the `spiffe` crate’s `X509Source`
(SPIRE Workload API).

It provides builders for `rustls::ClientConfig` and `rustls::ServerConfig` backed by a **live**
`X509Source`, ensuring that:

* Rotated SVIDs and trust bundles are automatically used for new TLS handshakes
* Mutual TLS (mTLS) authentication is enforced using SPIFFE identities
* Connection-level authorization is performed via SPIFFE ID checks

Cryptographic primitives and TLS mechanics are delegated entirely to `rustls`.

* See the [spiffe-rustls README](./spiffe-rustls/README.md) for configuration details and examples.

---

## Which crate should I use?

* **You want SPIFFE identity types or Workload API access** → use `spiffe`
* **You need direct access to SPIRE gRPC APIs** → use `spire-api`
* **You want mTLS with SPIFFE identities over rustls** → use `spiffe-rustls`

---

## Getting Started

Refer to the README of each individual crate for detailed setup instructions, examples, and API
documentation.

---

## License

This project is licensed under the [Apache License 2.0](./LICENSE).
