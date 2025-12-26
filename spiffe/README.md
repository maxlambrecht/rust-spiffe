# spiffe

[![Crates.io](https://img.shields.io/crates/v/spiffe.svg)](https://crates.io/crates/spiffe)
[![Docs.rs](https://docs.rs/spiffe/badge.svg)](https://docs.rs/spiffe/)
![MSRV](https://img.shields.io/badge/MSRV-1.83-blue)


A Rust library for interacting with the **SPIFFE Workload API**.

It provides idiomatic, standards-compliant access to SPIFFE identities and trust material, including:

- X.509 SVIDs and trust bundles
- JWT SVIDs and JWT bundles
- Streaming updates (watch semantics)
- Strongly typed SPIFFE primitives aligned with the SPIFFE specifications

For an introduction to SPIFFE, see <https://spiffe.io>.  
For the protocol definition, see the
[SPIFFE Workload API specification](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md).

---

## Installation

Add `spiffe` to your `Cargo.toml`:

```toml
[dependencies]
spiffe = "0.7.4"
````

---

## Quick start

### Create a Workload API client

Using an explicit socket path:

```rust
use spiffe::WorkloadApiClient;

let mut client = WorkloadApiClient::connect_to(
    "unix:///tmp/spire-agent/public/api.sock",
).await?;

```

Or via the `SPIFFE_ENDPOINT_SOCKET` environment variable:

```rust
use spiffe::WorkloadApiClient;

let mut client = WorkloadApiClient::connect_env().await?;
```

---

## X.509 identities

The Workload API client exposes low-level access to X.509 materials.

```rust
use spiffe::{TrustDomain, X509Context};

let context: X509Context = client.fetch_x509_context().await?;

let trust_domain = TrustDomain::new("example.org")?;
let bundle = context
    .bundle_set()
    .bundle_for_trust_domain(&trust_domain)?
    .ok_or("missing bundle")?;
```

### Watch for updates

```rust
use futures_util::StreamExt;

let mut stream = client.stream_x509_contexts().await?;

while let Some(update) = stream.next().await {
    let context = update?;
    // react to updated SVIDs and bundles
}
```

---

## `X509Source` (recommended)

`X509Source` is a higher-level abstraction built on top of the Workload API.

It maintains a locally cached, automatically refreshed view of X.509 SVIDs and bundles,
handling reconnections and rotations transparently.

```rust
use spiffe::{TrustDomain, X509Source};

let source = X509Source::new().await?;

// Snapshot of current materials
let context = source.x509_context()?;

// Selected SVID (default or picker)
let svid = source.svid()?;

// Bundle for a trust domain
let trust_domain = TrustDomain::new("example.org")?;
let bundle = source
    .bundle_for_trust_domain(&trust_domain)?
    .ok_or("missing bundle")?;
```

For most X.509-based workloads, **`X509Source` is the preferred API**.

---

## SVID hints

When multiple SVIDs are returned by the Workload API, SPIRE may attach an
**operator-defined hint** (for example, `internal` or `external`) to guide
selection.

Hints are **not part of the cryptographic identity**. They are metadata
returned by the Workload API and are exposed by this crate for convenience.

- X.509 hints are attached to `X509Svid`
- JWT hints are attached to `JwtSvid`

Higher-level abstractions like `X509Source` preserve hints and allow custom
selection logic via `SvidPicker`.

---

## JWT identities

JWT-based identity is accessed directly via the Workload API client.

### Fetch JWT SVIDs

```rust
use spiffe::SpiffeId;

let spiffe_id = SpiffeId::try_from("spiffe://example.org/my-service")?;

let jwt = client
    .fetch_jwt_svid(&["audience1", "audience2"], Some(&spiffe_id))
    .await?;
```

### Fetch and watch JWT bundles

```rust
use futures_util::StreamExt;
use spiffe::TrustDomain;

let bundles = client.fetch_jwt_bundles().await?;
let trust_domain = TrustDomain::try_from("example.org")?;
let bundle = bundles.bundle_for(&trust_domain)?;

let mut stream = client.stream_jwt_bundles().await?;
while let Some(update) = stream.next().await {
    let bundles = update?;
    // react to updated JWT authorities
}
```

## Features

### `workload-api` (default)

Enables the gRPC-based SPIFFE Workload API client.

This feature provides:
- `WorkloadApiClient` and streaming APIs
- X.509 and JWT SVID and bundle retrieval
- Streaming watch semantics over the Workload API
- gRPC transport and connection management

This feature is enabled by default.

### Disabling default features

The crate can be built without the Workload API client:

```toml
spiffe = { version = "0.7.4", default-features = false }
```

With default features disabled, the crate provides:

* Core SPIFFE types (`SpiffeId`, `TrustDomain`, etc.)
* X.509 and JWT SVID and bundle parsing and validation
* No networking or gRPC dependencies

This mode is useful when SPIFFE material is obtained out-of-band
or when networking support is not required.

---

## Documentation

Full API documentation and additional examples are available on
[docs.rs](https://docs.rs/spiffe).

---

## License

Licensed under the Apache License, Version 2.0.
See [LICENSE](../LICENSE) for details.
