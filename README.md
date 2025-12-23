# Rust SPIRE Libraries

[![Build](https://github.com/maxlambrecht/rust-spiffe/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/maxlambrecht/rust-spiffe/actions/workflows/ci.yml?query=branch%3Amain)
[![Coverage](https://coveralls.io/repos/github/maxlambrecht/rust-spiffe/badge.svg?branch=main)](https://coveralls.io/github/maxlambrecht/rust-spiffe?branch=main)
[![Docs](https://docs.rs/spiffe/badge.svg)](https://docs.rs/spiffe/)

This repository contains a set of Rust libraries focused on supporting SPIFFE and SPIRE
functionality across different layers of the stack.

## [spiffe](./spiffe)

The `spiffe` crate enables interaction with the
[SPIFFE Workload API](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md).
It supports fetching X.509 and JWT SVIDs, trust bundles, and watch/stream updates.

The types and behaviors in this crate are compliant with
[SPIFFE standards](https://github.com/spiffe/spiffe/tree/main/standards).
More information about SPIFFE can be found at [spiffe.io](https://spiffe.io/).

- [Read the README](./spiffe/README.md) for usage and API details.

## [spire-api](./spire-api)

The `spire-api` crate provides support for SPIRE-specific APIs, including the
Delegated Identity API and related SPIRE extensions.

- [Read the README](./spire-api/README.md) for more information.

## [spiffe-rustls](./spiffe-rustls)

The `spiffe-rustls` crate integrates SPIFFE identity with
[`rustls`](https://crates.io/crates/rustls) using the `spiffe` crate’s `X509Source`
(SPIRE Workload API).

It provides builders for `rustls::ClientConfig` and `rustls::ServerConfig` backed by a
live `X509Source`, enabling automatic use of rotated SVIDs and trust bundles in new TLS
handshakes. The crate focuses on authentication and connection-level authorization via SPIFFE IDs, while
delegating cryptography and TLS mechanics to `rustls`.

- [Read the README](./spiffe-rustls/README.md) for details and examples.

## Getting Started

Follow the links above to the individual README files for detailed information on how to
use each library.

## License

This project is licensed under the [Apache License 2.0](./LICENSE).
