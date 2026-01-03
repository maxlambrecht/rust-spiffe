# spiffe

[![Crates.io](https://img.shields.io/crates/v/spiffe.svg)](https://crates.io/crates/spiffe)
[![Docs.rs](https://docs.rs/spiffe/badge.svg)](https://docs.rs/spiffe/)
![MSRV](https://img.shields.io/badge/MSRV-1.85-blue)

A Rust library for interacting with the **SPIFFE Workload API**.

This crate provides idiomatic, standards-compliant access to SPIFFE identities and trust material, including:

* X.509 SVIDs and trust bundles
* JWT SVIDs and JWT bundles
* Streaming updates (watch semantics)
* Strongly typed SPIFFE primitives aligned with the SPIFFE specifications

For an introduction to SPIFFE, see [https://spiffe.io](https://spiffe.io).
For the protocol definition, see the
[SPIFFE Workload API specification](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md).

---

## Installation

Add `spiffe` to your `Cargo.toml`. All features are opt-in:

```toml
# For X.509 workloads (recommended)
[dependencies]
spiffe = { version = "0.9", features = ["x509-source"] }

# For direct Workload API client usage
[dependencies]
spiffe = { version = "0.9", features = ["workload-api"] }

# Minimal: only SPIFFE primitives (SpiffeId, TrustDomain)
[dependencies]
spiffe = "0.9"
```

---

## Quick start

### Create a Workload API client

Using an explicit socket path:

```rust
use spiffe::WorkloadApiClient;

let client = WorkloadApiClient::connect_to(
    "unix:/tmp/spire-agent/public/api.sock",
).await?;
```

Or via the `SPIFFE_ENDPOINT_SOCKET` environment variable:

```rust
use spiffe::WorkloadApiClient;

let client = WorkloadApiClient::connect_env().await?;
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
    .get(&trust_domain)
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
**operator-defined hint** (for example, `internal` or `external`) to guide selection.

Hints are **not part of the cryptographic identity**. They are metadata
returned by the Workload API and are exposed by this crate for convenience.

* X.509 hints are attached to `X509Svid`
* JWT hints are attached to `JwtSvid`

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
let bundle = bundles.get(&trust_domain);

let mut stream = client.stream_jwt_bundles().await?;
while let Some(update) = stream.next().await {
    let bundles = update?;
    // react to updated JWT authorities
}
```

---

## JWT verification modes

This crate supports **three distinct JWT-SVID usage patterns**, depending on where
verification happens.

### 1. Trusted by construction (no verification)

JWT-SVIDs **fetched directly from the SPIFFE Workload API** are trusted by construction.
The SPIRE agent already authenticated the workload and issued the token.

```rust
use spiffe::JwtSvid;

let svid = JwtSvid::from_workload_api_token(token_str)?;
```

No additional features are required.

---

### 2. Validation via the Workload API (recommended when available)

The Workload API exposes a validation RPC.
`WorkloadApiClient::validate_jwt_token` delegates verification to the SPIRE agent
and returns a parsed `JwtSvid`.

```rust
use spiffe::WorkloadApiClient;

let client = WorkloadApiClient::connect_env().await?;

let svid = client
    .validate_jwt_token("my-audience", jwt_token)
    .await?;
```

Characteristics:

* Signature verification is performed **by the SPIRE agent**
* No local cryptography required
* **Does not require any JWT verification feature**
* Recommended whenever the Workload API is reachable

---

### 3. Offline verification (explicit backend selection required)

If you need to validate **untrusted JWTs** locally (for example, tokens received
over the network), enable offline JWT verification with an explicit cryptographic
backend.

#### Using the pure-Rust backend (portable, recommended)

```toml
[dependencies]
spiffe = { version = "0.9", features = ["jwt-verify-rust-crypto"] }
```

#### Using the AWS-LC backend

```toml
[dependencies]
spiffe = { version = "0.9", features = ["jwt-verify-aws-lc-rs"] }
```

This enables local signature verification using JWT authorities from bundles:

```rust
use spiffe::JwtSvid;

let svid = JwtSvid::parse_and_validate(
    token_str,
    &bundle_source,
    &["expected-audience"],
)?;
```

Use this mode when:

* The Workload API is not available
* Tokens are received from external peers
* Fully offline validation is required

---

## Features

All features are additive and opt-in. The crate has **no default features** (`default = []`).

### Core features

#### `x509`

Enables X.509 SVID and bundle types plus parsing. Gates heavy ASN.1/X.509 dependencies (`asn1`, `x509-parser`, `pkcs8`).

**Note:** Most users should enable `x509-source` instead, which includes this feature automatically.

#### `transport`

Lightweight endpoint parsing and normalization. No runtime dependencies (pure parsing logic).

#### `transport-grpc`

gRPC connector for Unix/TCP endpoints. Requires `transport` and adds tokio/tonic/tower dependencies.

#### `workload-api`

Enables the async SPIFFE Workload API client. Requires `transport-grpc` and `x509`.

Provides:

* `WorkloadApiClient` and streaming APIs
* X.509 and JWT SVID and bundle retrieval
* Streaming watch semantics
* Agent-side JWT validation (`validate_jwt_token`)

#### `x509-source`

High-level X.509 watcher and caching abstraction. Requires `workload-api` (and transitively `x509`).

Provides:

* `X509Source` for automatic SVID/bundle watching and caching
* Automatic reconnection and rotation handling
* Recommended for most X.509-based workloads

#### `jwt`

Enables JWT SVID and bundle types plus parsing. Gates JWT-related dependencies (`serde`, `serde_json`, `time`, `base64ct`).

**Note:** JWT verification requires an additional backend feature (see below).

---

### JWT verification backends

#### `jwt-verify-rust-crypto`

Enables **offline JWT-SVID verification** using a **pure Rust cryptography backend**.

* Portable and dependency-light
* Recommended default for offline verification
* Required only when validating untrusted JWTs locally

---

### `jwt-verify-aws-lc-rs`

Enables **offline JWT-SVID verification** using **AWS-LC** via `aws-lc-rs`.

* Alternative cryptography backend
* Mutually exclusive with `jwt-verify-rust-crypto`

---

### Observability features

The crate supports optional observability through two mutually compatible features:
`logging` and `tracing`. Both features are optional and can be enabled independently
or together.

#### Feature precedence

When multiple observability features are enabled, the following precedence applies:

1. **`tracing`** (highest priority) — If enabled, all events are emitted via `tracing`
2. **`logging`** — If `tracing` is not enabled, events are emitted via the `log` crate
3. **No observability** — If neither feature is enabled, observability calls are no-ops

#### `logging`

Enables observability using the [`log`](https://crates.io/crates/log) crate.

This is a lightweight option suitable for applications that use the standard `log`
facade. Events are emitted via `log::debug!`, `log::info!`, `log::warn!`, and `log::error!`.

```toml
[dependencies]
spiffe = { version = "0.9", features = ["logging"] }
```

**Note:** The `logging` feature is not included in the default `workload-api` feature.
You must explicitly enable it if you want log output.

#### `tracing`

Enables structured observability using the [`tracing`](https://crates.io/crates/tracing) crate.

This is recommended for production environments that use structured logs, spans,
or distributed tracing systems. When both `tracing` and `logging` features are enabled,
**`tracing` takes precedence** and all events are emitted via `tracing` macros.

```toml
[dependencies]
spiffe = { version = "0.9", features = ["tracing"] }
```

**Note:** The `tracing` and `logging` features are not mutually exclusive. When both
features are enabled, events are emitted via `tracing`.

---

### Notes on JWT verification features

* Each backend feature (`jwt-verify-rust-crypto`, `jwt-verify-aws-lc-rs`) is self-contained and automatically includes the `jwt` feature
* Exactly **one** offline verification backend must be selected (mutually exclusive)
* Offline verification features are **not required** when using `WorkloadApiClient::validate_jwt_token`
* X.509-based functionality is unaffected by JWT verification features

---

## Quick Reference

### Common Operations

| Task                | Code                                                     |
|---------------------|----------------------------------------------------------|
| Create X.509 source | `X509Source::new().await?`                               |
| Get current SVID    | `source.svid()?`                                         |
| Get bundle          | `source.bundle_for_trust_domain(&td)?.ok_or("missing")?` |
| Fetch JWT SVID      | `client.fetch_jwt_svid(&["aud"], None).await?`           |
| Parse SPIFFE ID     | `SpiffeId::new("spiffe://td/path")?`                     |
| Check health        | `source.is_healthy()`                                    |
| Watch for updates   | `source.updated()`                                       |

### Error Handling

| Error Type                        | When It Occurs            |
|-----------------------------------|---------------------------|
| `X509SourceError::NoSuitableSvid` | Picker rejects all SVIDs  |
| `X509SourceError::Closed`         | Source was shut down      |
| `WorkloadApiError::EmptyResponse` | No data from Workload API |
| `SpiffeIdError::WrongScheme`      | Invalid SPIFFE ID format  |

---

## Documentation

Full API documentation and additional examples are available on
[docs.rs](https://docs.rs/spiffe).

---

## License

Licensed under the Apache License, Version 2.0.
See [LICENSE](../LICENSE) for details.
