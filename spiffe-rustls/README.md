# spiffe-rustls

[![Crates.io](https://img.shields.io/crates/v/spiffe-rustls.svg)](https://crates.io/crates/spiffe-rustls)
[![Docs.rs](https://docs.rs/spiffe-rustls/badge.svg)](https://docs.rs/spiffe-rustls/)
[![Safety](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance)
[![Rust 1.85+](https://img.shields.io/badge/rust-1.85+-orange.svg)](https://www.rust-lang.org)

`spiffe-rustls` integrates [`rustls`](https://crates.io/crates/rustls) with SPIFFE/SPIRE using the
[`spiffe`](https://crates.io/crates/spiffe) crate’s `X509Source` (SPIFFE Workload API).

It provides builders for `rustls::ClientConfig` and `rustls::ServerConfig` backed by a **live**
`X509Source`. When the SPIRE agent rotates X.509 SVIDs or trust bundles, **new TLS handshakes
automatically use the updated material**, without restarting the application.

The crate focuses on **TLS-level authentication and authorization via SPIFFE IDs**, while
delegating all cryptography and TLS mechanics to `rustls`.

---

## Key Features

- **Federation support** — Automatically handles multiple trust domains when SPIFFE federation is configured
- **Typed authorization** — Strongly-typed `Authorizer` trait for SPIFFE ID–based access control
- **Live updates** — Material rotates automatically when SPIRE updates SVIDs or bundles
- **Security-conscious design** — Zero unsafe code, conservative parsing, graceful degradation

---

## Quick Start

### 1. Create an `X509Source`

The source is configured via the `SPIFFE_ENDPOINT_SOCKET` environment variable.

```rust
let source = spiffe::X509Source::new().await?;
```

---

### 2. Build a client configuration (mTLS)

```rust
use spiffe_rustls::{authorizer, mtls_client};

let source = spiffe::X509Source::new().await?;

// Authorize only specific server SPIFFE IDs
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
trust domains. `spiffe-rustls` automatically handles this during certificate verification:

1. Extracts the peer’s SPIFFE ID from the certificate
2. Derives the trust domain from that SPIFFE ID
3. Selects the correct root certificate bundle from the bundle set
4. Verifies the certificate chain using the selected bundle

**No federation-specific configuration is required.**
Federation works automatically whenever the Workload API provides bundles for multiple
trust domains.

---

## Trust Domain Policy (verification)

You may optionally restrict which trust domains are allowed during **certificate verification**
using `TrustDomainPolicy`.

This is a **defense-in-depth** mechanism. The primary trust model comes from the bundle set
delivered by the Workload API.

```rust
use spiffe_rustls::TrustDomainPolicy;

// Default: trust all domains present in the Workload API bundle set
let policy = TrustDomainPolicy::AnyInBundleSet;

// Restrict verification to a fixed set of trust domains
let policy = TrustDomainPolicy::AllowList([
    "broker.example".try_into()?,
    "stockmarket.example".try_into()?,
].into_iter().collect());

// Restrict verification to exactly one trust domain
let policy = TrustDomainPolicy::LocalOnly("example.org".try_into()?);
```

> **Note:** Trust domain policy affects *verification only*.
> Authorization is handled separately via `Authorizer`.

---

## Authorization

Authorization is applied **after** cryptographic verification succeeds.

The crate provides a strongly-typed `Authorizer` trait and ergonomic constructors for
common authorization strategies.

### Common authorization patterns

```rust
use spiffe_rustls::authorizer;

// 1) Authentication only (allow any SPIFFE ID)
let auth = authorizer::any();

// 2) Allow only specific SPIFFE IDs
let auth = authorizer::exact([
    "spiffe://example.org/payment",
    "spiffe://example.org/checkout",
])?;

// 3) Allow any SPIFFE ID from specific trust domains
let auth = authorizer::trust_domains([
    "broker.example",
    "stockmarket.example",
])?;
```

### Custom authorization logic

```rust
use spiffe::SpiffeId;

// Custom rule using a closure
let auth = |peer: &SpiffeId| {
    peer.path().starts_with("/api/")
};
```

Closures automatically implement `Authorizer` and require no allocation.

---

## Client Configuration

### `ClientConfigBuilder`

Builds a `rustls::ClientConfig` that:

* presents the current SPIFFE X.509 SVID
* validates the server certificate chain using Workload API bundles
* automatically selects the correct trust domain
* authorizes the server by SPIFFE ID (URI SAN)

```rust
use spiffe_rustls::{authorizer, mtls_client, TrustDomainPolicy};

let source = spiffe::X509Source::new().await?;

let client_cfg = mtls_client(source)
    .authorize(authorizer::exact([
        "spiffe://example.org/myservice",
    ])?)
    .trust_domain_policy(
        TrustDomainPolicy::LocalOnly("example.org".try_into()?)
    )
    .build()?;
```

---

## Server Configuration

### `ServerConfigBuilder`

Builds a `rustls::ServerConfig` that:

* presents the current SPIFFE X.509 SVID
* requires and validates client certificates (mTLS)
* automatically selects the correct trust domain
* authorizes the client by SPIFFE ID (URI SAN)

```rust
use spiffe_rustls::{authorizer, mtls_server, TrustDomainPolicy};

let source = spiffe::X509Source::new().await?;

let server_cfg = mtls_server(source)
    .authorize(authorizer::trust_domains([
        "example.org",
    ])?)
    .trust_domain_policy(
        TrustDomainPolicy::LocalOnly("example.org".try_into()?)
    )
    .build()?;
```

---

## API Overview

### Builders

* `ClientConfigBuilder`
* `ServerConfigBuilder`

Each builder:

* retains an internal `Arc<X509Source>`
* always uses the **latest SVIDs and trust bundles**
* applies authorization **after** cryptographic verification

---

### Authorization helpers

* `authorizer::any()`
* `authorizer::exact()`
* `authorizer::trust_domains()`
* closures implementing `Fn(&SpiffeId) -> bool`

---

### Trust Domain Policy

* `TrustDomainPolicy::AnyInBundleSet` *(default)*
* `TrustDomainPolicy::AllowList`
* `TrustDomainPolicy::LocalOnly`

---

## Features

Most features are additive and opt-in.

**Crypto provider features are mutually exclusive — exactly one must be enabled.**

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

Provider choice affects only cryptographic primitives.
**SPIFFE semantics and API behavior are identical across providers.**

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

## Performance

`spiffe-rustls` is designed for production workloads:

- **Zero-copy certificate access** — SVIDs and bundles accessed via `Arc` references
- **Atomic updates** — New handshakes automatically use rotated material without locks
- **Efficient authorization** — `Authorizer` trait allows zero-allocation checks
- **Minimal overhead** — Authorization runs after TLS verification (no impact on handshake)

### Integration with Async Runtimes

The crate works seamlessly with:
- `tokio-rustls` for async TLS
- `tonic-rustls` for gRPC
- Any `rustls`-based TLS stack

See [examples](#examples) for integration patterns.

---

## Architecture

`spiffe-rustls` acts as a bridge between:

1. **`spiffe::X509Source`** — Provides live SVIDs and trust bundles
2. **`rustls`** — Handles all TLS cryptography and protocol
3. **Your application** — Receives verified, authorized connections

The integration is **non-invasive**:
- No modifications to `rustls` internals
- Standard `rustls::ClientConfig` and `rustls::ServerConfig` types
- Works with any `rustls`-compatible library

Authorization is applied **after** TLS verification succeeds, ensuring cryptographic security before policy checks.

---

## Security Considerations

* Certificates must contain **exactly one** SPIFFE ID URI SAN
* Trust bundles are sourced exclusively from the Workload API
* Trust domain selection is automatic and deterministic
* Authorization runs **after** cryptographic verification
* Material updates are atomic; new handshakes use fresh material

---

## Changelog

See [CHANGELOG.md](../CHANGELOG.md) for version history and migration guides.

---

## License

Licensed under the Apache License, Version 2.0.
See [LICENSE](../LICENSE) for details.
