# spire-api

[![Crates.io](https://img.shields.io/crates/v/spire-api.svg)](https://crates.io/crates/spire-api)
[![Docs.rs](https://docs.rs/spire-api/badge.svg)](https://docs.rs/spire-api)
![MSRV](https://img.shields.io/badge/MSRV-1.85-blue)

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
spire-api = "0.5"
```

---

## Quick start

The Delegated Identity API uses the **SPIRE Agent admin socket** (not the Workload API socket).
Set the `SPIRE_ADMIN_ENDPOINT_SOCKET` environment variable to the admin socket path:

```bash
export SPIRE_ADMIN_ENDPOINT_SOCKET="unix:///tmp/spire-agent/public/admin.sock"
```

### Fetch a delegated X.509 SVID

Using selector-based attestation:

```rust
use spire_api::{DelegatedIdentityClient, DelegateAttestationRequest};
use spire_api::selectors;

let client = DelegatedIdentityClient::connect_env().await?;

let x509_svid = client
    .fetch_x509_svid(DelegateAttestationRequest::Selectors(vec![
        selectors::Selector::Unix(selectors::Unix::Uid(1000)),
    ]))
    .await?;
```

Using PID-based attestation (let the agent attest the PID and generate selectors):

```rust
let x509_svid = client
    .fetch_x509_svid(DelegateAttestationRequest::Pid(1234))
    .await?;
```

### Fetch JWT SVIDs

```rust
let jwt_svids = client
    .fetch_jwt_svids(
        &["audience1", "audience2"],
        DelegateAttestationRequest::Selectors(vec![
            selectors::Selector::Unix(selectors::Unix::Uid(1000)),
        ]),
    )
    .await?;
```

### Fetch trust bundles

```rust
// X.509 bundles
let x509_bundles = client.fetch_x509_bundles().await?;

// JWT bundles
let jwt_bundles = client.fetch_jwt_bundles().await?;
```

### Streaming updates

The client also supports streaming methods for continuous updates:
- `stream_x509_svids()` - Stream X.509 SVID updates
- `stream_x509_bundles()` - Stream X.509 bundle updates
- `stream_jwt_bundles()` - Stream JWT bundle updates

---

## Delegated Identity API

The Delegated Identity API allows authorized workloads to obtain X.509 and JWT SVIDs (and bundles)
on behalf of other workloads that cannot be directly attested by the SPIRE agent.

**Important:** This API must be used over the SPIRE Agent **admin socket**, not the Workload API socket.
The admin socket path is typically configured via the `SPIRE_ADMIN_ENDPOINT_SOCKET` environment variable.

For background and protocol-level details, see the
[SPIRE Delegated Identity API documentation](https://spiffe.io/docs/latest/deploying/spire_agent/#delegated-identity-api).

---

## Documentation

Full API documentation is available on [docs.rs](https://docs.rs/spire-api).

---

## License

Licensed under the Apache License, Version 2.0.
See [LICENSE](../LICENSE) for details.
