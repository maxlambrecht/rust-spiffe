# spire-api

[![Crates.io](https://img.shields.io/crates/v/spire-api.svg)](https://crates.io/crates/spire-api)
[![Docs.rs](https://docs.rs/spire-api/badge.svg)](https://docs.rs/spire-api)
![MSRV](https://img.shields.io/badge/MSRV-1.83-blue)

A Rust library providing access to **SPIRE-specific gRPC APIs** that are not part of the core SPIFFE
standards.

This crate is intended for applications and services that need to interact directly with SPIRE agent
or server APIs beyond the Workload API.

---

## Scope

Currently supported APIs include:

- **Delegated Identity API**  
  Allows authorized workloads to obtain X.509 and JWT SVIDs (and bundles) on behalf of other workloads
  that cannot be directly attested by the SPIRE agent.

This is particularly useful in advanced or constrained environments where direct workload
attestation is not feasible.

---

## Installation

Add `spire-api` to your `Cargo.toml`:

```toml
[dependencies]
spire-api = "0.3.9"
````

---

## Quick start

Fetch a delegated X.509 SVID using selector-based attestation:

```rust
use spire_api::DelegatedIdentityClient;
use spire_api::selectors;

let client = DelegatedIdentityClient::default().await?;

let x509_svid = client
    .fetch_x509_svid(spire_api::DelegateAttestationRequest::Selectors(vec![
        selectors::Selector::Unix(selectors::Unix::Uid(1000)),
    ]))
    .await?;
```

JWT SVIDs and trust bundles can be fetched using the corresponding client methods.

---

## Delegated Identity API

For background and protocol-level details, see the
[SPIRE Delegated Identity API documentation](https://spiffe.io/docs/latest/spire/using/getting-started/).

---

## Documentation

Full API documentation is available on [docs.rs](https://docs.rs/spire-api).

---

## License

Licensed under the Apache License, Version 2.0.
See [LICENSE](../LICENSE) for details.
