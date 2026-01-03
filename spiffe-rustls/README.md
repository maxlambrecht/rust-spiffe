# spiffe-rustls

[![Crates.io](https://img.shields.io/crates/v/spiffe-rustls.svg)](https://crates.io/crates/spiffe-rustls)
[![Docs.rs](https://docs.rs/spiffe-rustls/badge.svg)](https://docs.rs/spiffe-rustls/)
![MSRV](https://img.shields.io/badge/MSRV-1.85-blue)

`spiffe-rustls` integrates [`rustls`](https://crates.io/crates/rustls) with SPIFFE/SPIRE using the
[`spiffe`](https://crates.io/crates/spiffe) crate’s `X509Source` (SPIFFE Workload API).

It provides builders for `rustls::ClientConfig` and `rustls::ServerConfig` backed by a **live**
`X509Source`. When the SPIRE agent rotates SVIDs or trust bundles, **new TLS handshakes automatically
use the updated material**, without restarting the application.

The crate focuses on **TLS-level authentication and authorization via SPIFFE IDs**, while delegating
all cryptography and TLS mechanics to `rustls`.

---

## Key Features

* **Federation support** — Automatically handles multiple trust domains when SPIFFE federation is configured
* **Typed authorization** — Strongly-typed `Authorizer` trait for SPIFFE ID–based access control
* **Live updates** — Material rotates automatically when SPIRE updates SVIDs or bundles
* **Production-ready** — Zero unsafe code, conservative parsing, graceful degradation

---

## Quick Start

### 1. Create an `X509Source`

The source is configured via `SPIFFE_ENDPOINT_SOCKET`:

```rust
let source = spiffe::X509Source::new().await?;
```

---

### 2. Build a rustls client configuration

```rust
use spiffe_rustls::{authorizer, mtls_client};

let source = spiffe::X509Source::new().await?;

// Pass string literals directly — exact() will convert them
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

**No federation-specific configuration is required.**
Federation works automatically whenever the Workload API provides bundles for multiple trust domains.

---

### Trust Domain Policy

You may optionally restrict which trust domains are accepted using [`TrustDomainPolicy`].
This is a **defense-in-depth** mechanism—the primary trust model comes from the bundle set
delivered by the Workload API.

```rust
use spiffe_rustls::{AllowList, AnyInBundleSet, LocalOnly, TrustDomainPolicy};
use std::collections::BTreeSet;

// Choose exactly one policy variant:

// Default: use all bundles from the Workload API
let policy = AnyInBundleSet;

// Restrict to specific trust domains
let mut allowed = BTreeSet::new();
allowed.insert("broker.example".try_into()?);
allowed.insert("stockmarket.example".try_into()?);
let policy = AllowList(allowed);

// Only trust a single trust domain
let policy = LocalOnly("example.org".try_into()?);

// Full path variant (equivalent)
let policy = TrustDomainPolicy::AnyInBundleSet;
```

---

## Authorization

Authorization is performed **after** cryptographic verification succeeds.

The crate provides a strongly-typed [`Authorizer`] trait for SPIFFE ID–based authorization.

### Using the `Authorizer` trait

```rust
use spiffe_rustls::{Authorizer, authorizer};
use spiffe::SpiffeId;
use std::sync::Arc;

// Accept any SPIFFE ID (authentication only)
let auth: Arc<dyn Authorizer> = Arc::new(authorizer::any());

// Accept only exact SPIFFE IDs
let auth = authorizer::exact([
    "spiffe://example.org/payment",
    "spiffe://example.org/checkout",
])?;

// Accept any SPIFFE ID from specific trust domains
let auth = authorizer::trust_domains([
    "broker.example",
    "stockmarket.example",
])?;

// Custom authorization logic
let auth: Arc<dyn Authorizer> = Arc::new(|peer: &SpiffeId| {
    peer.path().starts_with("/payment/")
});
```

---

## API Overview

### Builders

* `ClientConfigBuilder` — builds `rustls::ClientConfig`
* `ServerConfigBuilder` — builds `rustls::ServerConfig`

Each builder:

* retains an `Arc<X509Source>` internally
* always uses the **latest SVIDs and trust bundles**
* authorizes peers by SPIFFE ID (URI SAN)

---

### Authorization helpers

* [`Authorizer`] — trait for SPIFFE ID–based authorization
* `authorizer::any()`
* `authorizer::exact()`
* `authorizer::trust_domains()`

---

### Trust Domain Policy types

* [`TrustDomainPolicy`]
* `AnyInBundleSet` — use all bundles from the Workload API (default)
* `AllowList` — restrict to specific trust domains
* `LocalOnly` — trust exactly one trust domain

Policy variants are re-exported at the crate root for convenience.

---

## Client Configuration

### `ClientConfigBuilder`

Builds a `rustls::ClientConfig` that:

* presents the current SPIFFE X.509 SVID
* validates the server certificate chain using Workload API bundles
* selects the correct trust domain automatically
* authorizes the server by SPIFFE ID

```rust
use spiffe_rustls::{authorizer, mtls_client, AllowList};
use std::collections::BTreeSet;

let source = spiffe::X509Source::new().await?;

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

---

## Server Configuration

### `ServerConfigBuilder`

Builds a `rustls::ServerConfig` that:

* presents the current SPIFFE X.509 SVID
* requires and validates client certificates (mTLS)
* selects the correct trust domain automatically
* authorizes the client by SPIFFE ID

```rust
use spiffe::{TrustDomain, X509Source};
use spiffe_rustls::{authorizer, mtls_server, LocalOnly};

let source = X509Source::new().await?;

let allowed_trust_domains = ["example.org"];
let local_trust_domain: TrustDomain = "example.org".try_into()?;

let server_cfg = mtls_server(source)
    .authorize(authorizer::trust_domains(allowed_trust_domains)?)
    .trust_domain_policy(LocalOnly(local_trust_domain))
    .build()?;
```

---

## Features

Most features are additive and opt-in.
**Crypto provider features are mutually exclusive—exactly one must be enabled.**

### Crypto providers

```toml
[features]
default = ["ring"]
ring = ["rustls/ring"]
aws-lc-rs = ["rustls/aws_lc_rs"]
```

* **Default:** `ring`
* **Optional:** `aws-lc-rs`

Example (AWS-LC):

```bash
cargo add spiffe-rustls --no-default-features --features aws-lc-rs
```

Provider choice affects only cryptographic primitives; **SPIFFE semantics and API behavior
are identical** across providers.

---

### Observability

Observability is optional and controlled via features:

* `logging` — emit events via the `log` crate
* `tracing` — emit events via the `tracing` crate

Both features are **disabled by default**.

#### Precedence

1. `tracing` (if enabled)
2. `logging` (only if `tracing` is disabled)
3. no-op (if neither is enabled)

Example:

```toml
spiffe-rustls = { version = "0.2", features = ["tracing"] }
```

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

### Raw TLS (`tokio-rustls`)

```bash
cargo run --example mtls_tcp_server
cargo run --example mtls_tcp_client
```

---

### gRPC (`tonic-rustls`)

gRPC examples live in a **separate crate** (`spiffe-rustls-grpc-examples`) to avoid pulling
gRPC/protobuf dependencies into the library.

```bash
cargo run -p spiffe-rustls-grpc-examples --bin grpc_server_mtls
cargo run -p spiffe-rustls-grpc-examples --bin grpc_client_mtls
```

---

## Security Considerations

* Certificates must contain **exactly one** SPIFFE ID URI SAN
* Trust bundles come exclusively from the Workload API
* Trust domain selection is automatic and deterministic
* Authorization runs **after** cryptographic verification
* Material updates are atomic; new handshakes use fresh material

---

## License

Licensed under the Apache License, Version 2.0.
See [LICENSE](../LICENSE) for details.
