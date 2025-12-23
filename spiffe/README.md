# Rust SPIFFE

A Rust library for interacting with the **SPIFFE Workload API**.

It provides idiomatic access to SPIFFE identities and trust material, including:

- X.509 SVIDs and bundles
- JWT SVIDs and bundles
- Streaming updates (watch semantics)
- Strongly typed SPIFFE primitives compliant with the SPIFFE standards

For background on SPIFFE, see <https://spiffe.io>.  
For the Workload API specification, see the
[SPIFFE Workload API standard](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md).

[![crates.io](https://img.shields.io/crates/v/spiffe.svg)](https://crates.io/crates/spiffe)
[![Build](https://github.com/maxlambrecht/rust-spiffe/actions/workflows/ci.yml/badge.svg)](https://github.com/maxlambrecht/rust-spiffe/actions/workflows/ci.yml)
[![docs.rs](https://docs.rs/spiffe/badge.svg)](https://docs.rs/spiffe)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

---

## Installation

Add `spiffe` to your `Cargo.toml`:

```toml
[dependencies]
spiffe = "0.7.1"
````

This includes both core SPIFFE types and a Workload API client.

---

## Quick start

### Create a Workload API client

Using an explicit socket path:

```rust
use spiffe::WorkloadApiClient;

let client = WorkloadApiClient::new_from_path(
    "unix:///tmp/spire-agent/public/api.sock",
).await?;
```

Or via the `SPIFFE_ENDPOINT_SOCKET` environment variable:

```rust
use spiffe::WorkloadApiClient;

let client = WorkloadApiClient::default().await?;
```

---

## X.509 identities

The Workload API client provides **direct, low-level access** to X.509 materials.

```rust
use spiffe::{TrustDomain, X509Context};

let svid = client.fetch_x509_svid().await?;
let bundles = client.fetch_x509_bundles().await?;
let context: X509Context = client.fetch_x509_context().await?;

let trust_domain = TrustDomain::try_from("example.org")?;
let bundle = bundles.get_bundle(&trust_domain)?;
```

### Watch for updates

```rust
use futures_util::StreamExt;

let mut stream = client.stream_x509_contexts().await?;

while let Some(update) = stream.next().await {
    let context = update?;
    // react to updated SVIDs / bundles
}
```

---

## X509Source (recommended)

`X509Source` provides a **higher-level abstraction** over the Workload API for
X.509-based workloads.

It maintains a locally cached, automatically refreshed view of SVIDs and bundles,
and transparently handles reconnections and rotations.

```rust
use spiffe::{TrustDomain, X509Source};

let source = X509Source::new().await?;

// Snapshot of the current X.509 materials
let context = source.x509_context();

// Default SVID
let svid = context.default_svid()?;

// Bundle for a trust domain
let trust_domain = TrustDomain::try_from("example.org")?;
let bundle = context.bundles().get_bundle(&trust_domain)?;
```

For most applications that rely on X.509 identities, **`X509Source` is the preferred API**.

---

## JWT identities

JWT-based identity is accessed via the Workload API client.

### Fetch JWT SVIDs

```rust
use spiffe::{JwtSvid, SpiffeId};

let spiffe_id = SpiffeId::try_from("spiffe://example.org/my-service")?;

let jwt = client
    .fetch_jwt_svid(&["audience1", "audience2"], Some(&spiffe_id))
    .await?;
```

### Fetch JWT bundles

```rust
use spiffe::TrustDomain;

let bundles = client.fetch_jwt_bundles().await?;
let trust_domain = TrustDomain::try_from("example.org")?;
let bundle = bundles.get_bundle(&trust_domain)?;
```

### Watch JWT bundle updates

```rust
use futures_util::StreamExt;

let mut stream = client.stream_jwt_bundles().await?;

while let Some(update) = stream.next().await {
    let bundles = update?;
    // react to updated JWT authorities
}
```

---

## Documentation

API documentation and additional examples are available on [docs.rs](https://docs.rs/spiffe).

---

## License

Licensed under the Apache License, Version 2.0.
See [LICENSE](../LICENSE) for details.
