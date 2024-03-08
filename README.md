# Rust SPIRE Libraries

[![Build](https://github.com/maxlambrecht/rust-spiffe/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/maxlambrecht/rust-spiffe/actions/workflows/ci.yml?query=branch%3Amain)
[![Coverage](https://coveralls.io/repos/github/maxlambrecht/rust-spiffe/badge.svg?branch=main)](https://coveralls.io/github/maxlambrecht/rust-spiffe?branch=main)
[![Docs](https://docs.rs/spiffe/badge.svg)](https://docs.rs/spiffe/)

This repository contains two distinct Rust libraries focused on supporting SPIRE functionalities:

## [spiffe](./spiffe)

The `spiffe` crate enables interaction with
the [SPIFFE Workload API](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md). It allows
fetching of X.509 and JWT SVIDs, bundles, and supports watch/stream updates. The types in the library are in compliance
with [SPIFFE standards](https://github.com/spiffe/spiffe/tree/main/standards). More about SPIFFE can be found
at [spiffe.io](https://spiffe.io/).

- [Read the README](./spiffe/README.md) for more information.

## [spire-api](./spire-api)

The `spire-api` crate provides support for SPIRE specific APIs, including the Delegated Identity API.

- [Read the README](./spire-api/README.md) for more information.

## Getting Started

Follow the links above to the individual README files for detailed information on how to use each library.

## License

This project is licensed under [LICENSE NAME](./LICENSE).
