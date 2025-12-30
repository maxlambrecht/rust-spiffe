# spiffe-rustls

[![Crates.io](https://img.shields.io/crates/v/spiffe-rustls.svg)](https://crates.io/crates/spiffe-rustls)
[![Docs.rs](https://docs.rs/spiffe-rustls/badge.svg)](https://docs.rs/spiffe-rustls/)
![MSRV](https://img.shields.io/badge/MSRV-1.83-blue)

`spiffe-rustls` integrates [`rustls`](https://crates.io/crates/rustls) with SPIFFE/SPIRE using the
[`spiffe`](https://crates.io/crates/spiffe) crate's `X509Source` (SPIFFE Workload API).

It provides builders for `rustls::ClientConfig` and `rustls::ServerConfig` backed by a **live**
`X509Source`. When the SPIRE agent rotates SVIDs or trust bundles, **new TLS handshakes automatically
use the updated material**, without restarting the application.

The crate focuses on **TLS authentication and connection-level authorization via SPIFFE IDs**, while
delegating all cryptography and TLS mechanics to `rustls`.

## Key Features

* **Federation support**: Automatically handles multiple trust domains when SPIFFE federation is configured
* **Typed authorization**: Strongly-typed `Authorizer` trait for SPIFFE ID-based access control
* **Live updates**: Material rotates automatically when SPIRE updates SVIDs or bundles
* **Production-ready**: Zero unsafe code, comprehensive error handling, graceful degradation

---

## Quick Start

### 1. Create an X509Source

The source is configured via `SPIFFE_ENDPOINT_SOCKET`:

```rust
let source = spiffe::X509Source::new().await?;
```

### 2. Build a rustls client configuration

```rust
use spiffe_rustls::{authorizer, mtls_client};

let source = spiffe::X509Source::new().await?;

// Pass string literals directly - exact() and trust_domains() will convert them
let client_cfg = mtls_client(source)
    .authorize(authorizer::exact([
        "spiffe://example.org/myservice",
        "spiffe://example.org/myservice2",
    ])?)
    .build()?;
```

The resulting `ClientConfig` can be used directly with `rustls`, or integrated into
`tokio-rustls`, `tonic-rustls`, or similar libraries.

---

## Federation

When SPIFFE federation is configured, the Workload API delivers trust bundles for multiple
trust domains. `spiffe-rustls` automatically handles this:

1. **Extracts the SPIFFE ID** from the peer certificate
2. **Derives the trust domain** from that SPIFFE ID
3. **Selects the correct root certificate bundle** from the bundle set
4. **Verifies the certificate chain** using the selected bundle

**No federation-specific configuration is required.** Federation works automatically whenever
the Workload API provides bundles for multiple trust domains. The verifier dynamically selects
the correct trust domain based on the peer's SPIFFE ID.

### Trust Domain Policy

You can optionally restrict which trust domains are accepted using [`TrustDomainPolicy`].
This is a **defense-in-depth** mechanism—the primary trust model comes from the bundle set
delivered by the Workload API.

```rust
use spiffe_rustls::{AllowList, AnyInBundleSet, LocalOnly, TrustDomainPolicy};
use std::collections::BTreeSet;

// Default: use all bundles from the Workload API
let policy = AnyInBundleSet;

// Restrict to specific trust domains
let mut allowed = BTreeSet::new();
allowed.insert("broker.example".try_into()?);
allowed.insert("stockmarket.example".try_into()?);
let policy = AllowList(allowed);

// Only trust a single trust domain
let policy = LocalOnly("example.org".try_into()?);

// You can also use the full path if preferred
let policy = TrustDomainPolicy::AnyInBundleSet;
```

---

## Authorization

Authorization is performed **after** cryptographic verification succeeds. The crate provides a
strongly-typed [`Authorizer`] trait for implementing authorization policies.

### Using the Authorizer Trait

The new `Authorizer` trait works with strongly-typed `SpiffeId` values:

```rust
use spiffe_rustls::{Authorizer, authorizer};
use spiffe::SpiffeId;
use std::sync::Arc;

// Accept any SPIFFE ID (authentication only)
let auth: Arc<dyn Authorizer> = Arc::new(authorizer::any());

// Accept only exact SPIFFE IDs - pass string literals directly
let auth = authorizer::exact([
    "spiffe://example.org/payment",
    "spiffe://example.org/checkout",
])?;

// Accept any SPIFFE ID from specific trust domains - pass string literals directly
let auth = authorizer::trust_domains([
    "broker.example",
    "stockmarket.example",
])?;

// Custom authorizer using a closure
let auth: Arc<dyn Authorizer> = Arc::new(|peer: &SpiffeId| {
    peer.path().starts_with("/payment/")
});
```

---

## API Overview

The public API consists of:

### Builders

* `ClientConfigBuilder` - builds `rustls::ClientConfig`
* `ServerConfigBuilder` - builds `rustls::ServerConfig`

Each builder:

* retains an `Arc<X509Source>`
* builds a `rustls::{ClientConfig, ServerConfig}`
* always uses the **latest SVIDs and trust bundles**
* authorizes peers by SPIFFE ID (URI SAN)

### Authorization Types

* [`Authorizer`] - trait for SPIFFE ID-based authorization
* `authorizer::any()` - accept any SPIFFE ID
* `authorizer::exact()` - accept only exact SPIFFE IDs
* `authorizer::trust_domains()` - accept any SPIFFE ID from specific trust domains

### Policy Types

* [`TrustDomainPolicy`] - optional policy for restricting which trust domains are accepted
* `AnyInBundleSet` (or `TrustDomainPolicy::AnyInBundleSet`) - use all bundles from the Workload API (default)
* `AllowList` (or `TrustDomainPolicy::AllowList`) - restrict to specific trust domains
* `LocalOnly` (or `TrustDomainPolicy::LocalOnly`) - only trust a single trust domain

Policy variants are re-exported at the crate root for convenience, so you can use `AllowList(domains)` instead of `TrustDomainPolicy::AllowList(domains)`.

---

## Client Configuration

### ClientConfigBuilder

Builds a `rustls::ClientConfig` that:

* presents the current SPIFFE X.509 SVID as the client certificate
* validates the server certificate chain using bundles from the Workload API
* automatically selects the correct trust domain bundle based on the server's SPIFFE ID
* authorizes the server by SPIFFE ID (URI SAN)

**Example:**

```rust
use spiffe_rustls::{authorizer, mtls_client, AllowList};
use std::collections::BTreeSet;

let source = spiffe::X509Source::new().await?;

// Pass string literals directly - exact() will convert them
let allowed_server_ids = [
    "spiffe://example.org/myservice",
    "spiffe://example.org/myservice2",
];

let mut allowed_trust_domains = BTreeSet::new();
allowed_trust_domains.insert("example.org".try_into()?);

let client_cfg = mtls_client(source)
    .authorize(authorizer::exact(allowed_server_ids)?)
    .trust_domain_policy(AllowList(allowed_trust_domains))
    .build()?;
```

The builder automatically handles multiple trust domains when SPIFFE federation is configured.
No federation-specific configuration is required.

---

## Server Configuration

### ServerConfigBuilder

Builds a `rustls::ServerConfig` that:

* presents the current SPIFFE X.509 SVID as the server certificate
* requires and validates client certificates (mTLS)
* automatically selects the correct trust domain bundle based on the client's SPIFFE ID
* authorizes the client by SPIFFE ID (URI SAN)

**Example:**

```rust
use spiffe::{TrustDomain, X509Source};
use spiffe_rustls::{authorizer, mtls_server, LocalOnly};

let source = X509Source::new().await?;

// Pass string literals directly - trust_domains() will convert them
let allowed_trust_domains = ["example.org"];

let local_trust_domain: TrustDomain = "example.org".try_into()?;

let server_cfg = mtls_server(source)
    .authorize(authorizer::trust_domains(allowed_trust_domains)?)
    .trust_domain_policy(LocalOnly(local_trust_domain))
    .build()?;
```
<｜tool▁calls▁begin｜><｜tool▁call▁begin｜>
read_file

The builder automatically handles multiple trust domains when SPIFFE federation is configured.
No federation-specific configuration is required.

---

## Features

### Crypto Providers

`spiffe-rustls` supports multiple `rustls` crypto providers:

```toml
[features]
default = ["ring"]
ring = ["rustls/ring"]
aws-lc-rs = ["rustls/aws_lc_rs"]
```

* **Default:** `ring`
* **Optional:** `aws-lc-rs`

Exactly **one** provider must be enabled. Enabling more than one results in a compile-time error.

Example (AWS-LC):

```bash
cargo add spiffe-rustls --no-default-features --features aws-lc-rs
```

Provider choice affects only cryptographic primitives; **SPIFFE semantics and API behavior are
identical** across providers.

### Tracing

By default, `spiffe-rustls` uses the [`log`](https://crates.io/crates/log) crate for observability.
To use [`tracing`](https://crates.io/crates/tracing) instead, enable the `tracing` feature:

```toml
[dependencies]
spiffe-rustls = { version = "0.2", features = ["tracing"] }
```

When the `tracing` feature is enabled, all log statements are emitted as tracing events instead.
This allows you to use tracing's structured logging, spans, and integration with observability
platforms.

---

## Examples

### Prerequisites

All examples require:

* a running **SPIRE agent**
* a valid Workload API socket (`SPIFFE_ENDPOINT_SOCKET`)
* local DNS resolution for `example.org`

For local testing, add to `/etc/hosts`:

```text
127.0.0.1 example.org
```

---

### Raw TLS (tokio-rustls)

Direct TLS integration using `tokio-rustls`.

Examples:

* `mtls_tcp_server.rs`
* `mtls_tcp_client.rs`

```bash
cargo run --features tcp-examples --example mtls_tcp_server
cargo run --features tcp-examples --example mtls_tcp_client
```

---

### gRPC (tonic + tonic-rustls)

gRPC examples live in a **separate crate** (`spiffe-rustls-grpc-examples`) to avoid pulling gRPC and
protobuf build dependencies into the library.

```bash
cargo run -p spiffe-rustls-grpc-examples --bin grpc_server_mtls
cargo run -p spiffe-rustls-grpc-examples --bin grpc_client_mtls
```

---

## Security Considerations

### Certificate Verification

* Certificates are verified against the trust bundle set delivered by the Workload API
* Only certificates with exactly **one** SPIFFE ID URI SAN are accepted (per SPIFFE spec)
* The verifier automatically selects the correct trust domain based on the peer's SPIFFE ID
* Authorization runs **after** cryptographic verification succeeds

### Trust Domain Policy

The `TrustDomainPolicy` is a **defense-in-depth** mechanism. The primary trust model comes from
the bundle set delivered by the Workload API. When SPIFFE federation is configured, the Workload
API provides bundles for multiple trust domains, and the policy allows you to restrict which of
those bundles are actually used during certificate verification.

### Authorization

By default, the builder accepts any SPIFFE ID (authentication only, no authorization).
Use `authorizer::exact()` or `authorizer::trust_domains()` to restrict which SPIFFE IDs
are accepted. Use `authorizer::any()` explicitly if you want to make it clear that
authorization is performed at another layer (e.g., application-level RBAC).

---

## Notes

* Examples rely exclusively on the SPIFFE Workload API; they do not start or configure SPIRE.
* Standard TLS name (SNI) verification still applies; the DNS name must match the certificate SAN.
* Material updates are atomic; new handshakes use the latest material without blocking.

---

## License

Licensed under the Apache License, Version 2.0.
See [LICENSE](../LICENSE) for details.
