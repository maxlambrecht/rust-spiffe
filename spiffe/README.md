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
spiffe = "0.6.7"
````

This includes both SPIFFE core types and a Workload API client.

---

## Quick Start

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

### Fetch X.509 materials directly

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
let mut stream = client.stream_x509_contexts().await?;

while let Some(update) = stream.next().await {
    let context = update?;
    // react to updated SVIDs / bundles
}
```

---

## X.509Source (recommended)

`X509Source` maintains a locally cached, automatically refreshed view of X.509
SVIDs and bundles.

```rust
use spiffe::X509Source;

let source = X509Source::new().await?;

// Default SVID
let svid = source.get_svid()?.expect("no SVID available");

// Bundle for a trust domain
let bundle = source
    .get_bundle_for_trust_domain(&"example.org".try_into()?)?
    .expect("no bundle found");
```

---

## JWT identities

### Fetch and validate JWT SVIDs

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
