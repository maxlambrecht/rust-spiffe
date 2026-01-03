#![deny(missing_docs)]
#![deny(unsafe_code)]
#![warn(missing_debug_implementations)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![warn(clippy::unwrap_used)]
#![warn(clippy::expect_used)]

//! This crate provides Rust bindings for the
//! [SPIFFE Workload API](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md).
//!
//! It allows workloads to fetch and watch SPIFFE-issued X.509 and JWT SVIDs,
//! trust bundles, and related metadata, using strongly typed APIs aligned with
//! the SPIFFE standards.
//!
//! ## Feature Matrix
//!
//! | Feature | Description |
//! |---------|-------------|
//! | `x509` | X.509 SVID and bundle types + parsing (gates heavy ASN.1/X.509 deps) |
//! | `transport` | Endpoint parsing (no runtime deps) |
//! | `transport-grpc` | gRPC connector |
//! | `workload-api` | Async Workload API client |
//! | `workload` | Convenience feature for `workload-api` (recommended for direct client usage) |
//! | `x509-source` | High-level X.509 watcher/caching |
//! | `jwt` | JWT SVID and bundle types |
//! | `jwt-verify-rust-crypto` | JWT verification (rust-crypto backend) |
//! | `jwt-verify-aws-lc-rs` | JWT verification (aws-lc-rs backend) |
//! | `logging` | Log-based observability |
//! | `tracing` | Tracing-based observability |
//!
//! **Note:** The `x509` feature gates heavy X.509 parsing dependencies. The `workload-api` feature
//! enables the async Workload API client. Most users wanting X.509 functionality should enable
//! `x509-source`, which automatically enables `x509` and `workload-api`. For direct client usage,
//! enable the `workload` feature.
//!
//! For X.509-based workloads, the primary entry point is [`X509Source`] (requires
//! the `x509-source` feature). It maintains a cached view of the latest X.509
//! materials and automatically tracks SVID and bundle rotation.
//!
//! For advanced X.509 source configuration, see the [`x509_source`] module.
//!
//! ## X.509 (recommended)
//!
//! ```no_run
//! # #[cfg(feature = "x509-source")]
//! # async fn example() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//! use spiffe::{TrustDomain, X509Source};
//!
//! // Connect to the Workload API using SPIFFE_ENDPOINT_SOCKET.
//! let source = X509Source::new().await?;
//!
//! // Snapshot of current X.509 materials (SVIDs + bundles).
//! let context = source.x509_context()?;
//!
//! // Access the default SVID.
//! let svid = context.default_svid().ok_or("missing svid")?;
//!
//! // Inspect the certificate chain and private key.
//! let _cert_chain = svid.cert_chain();
//! let _private_key = svid.private_key();
//!
//! // Access trust bundles by trust domain.
//! let trust_domain = TrustDomain::try_from("example.org")?;
//! let _bundle = context
//!     .bundle_set()
//!     .get(&trust_domain)
//!     .ok_or("missing bundle")?;
//!
//! # Ok(())
//! # }
//! ```
//!
//! ## JWT SVIDs
//!
//! ```no_run
//! # #[cfg(all(feature = "workload-api", feature = "jwt"))]
//! # async fn example() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//! use spiffe::WorkloadApiClient;
//!
//! let client = WorkloadApiClient::connect_env().await?;
//!
//! let audiences = &["service-a"];
//! let jwt_svid = client.fetch_jwt_svid(audiences, None).await?;
//!
//! let _claims = jwt_svid.claims();
//! # Ok(())
//! # }
//! ```

pub mod bundle;
#[cfg(feature = "x509")]
pub mod cert;
pub mod constants;
pub mod spiffe_id;
pub mod svid;

mod observability;
mod prelude;

/// Transport primitives (endpoint parsing, optional gRPC connector).
///
/// Enabled with `transport` (parsing only) or `transport-grpc` (parsing + gRPC connector).
#[cfg(any(feature = "transport", feature = "transport-grpc"))]
pub mod transport;

// Compile-time guards for feature combinations
#[cfg(all(feature = "jwt-verify-rust-crypto", feature = "jwt-verify-aws-lc-rs"))]
compile_error!(
    "Cannot enable both JWT verification backends simultaneously. \
     Choose exactly one: `jwt-verify-rust-crypto` or `jwt-verify-aws-lc-rs`."
);

#[cfg(any(
    feature = "workload-api",
    feature = "workload-api-x509",
    feature = "workload-api-jwt",
    feature = "workload-api-full"
))]
pub mod workload_api;

#[cfg(feature = "x509-source")]
pub mod x509_source;

// Core identifiers
pub use crate::spiffe_id::{SpiffeId, SpiffeIdError, TrustDomain};

// SVIDs
#[cfg(feature = "jwt")]
pub use crate::svid::jwt::{JwtSvid, JwtSvidError};
#[cfg(feature = "x509")]
pub use crate::svid::x509::{X509Svid, X509SvidError};

// Bundles
#[cfg(feature = "jwt")]
pub use crate::bundle::jwt::{JwtBundle, JwtBundleError, JwtBundleSet};
#[cfg(feature = "x509")]
pub use crate::bundle::x509::{X509Bundle, X509BundleError, X509BundleSet};

// Workload API - Common types
//
// WorkloadApiClient and X509Context. Available with `workload-api` feature.
#[cfg(any(
    feature = "workload-api",
    feature = "workload-api-x509",
    feature = "workload-api-full"
))]
pub use crate::workload_api::X509Context;
#[cfg(any(
    feature = "workload-api",
    feature = "workload-api-x509",
    feature = "workload-api-jwt",
    feature = "workload-api-full"
))]
pub use crate::workload_api::{WorkloadApiClient, WorkloadApiError};

// X.509 Source
//
// High-level watcher/caching abstraction. Available with `x509-source` feature.
// Primary types are re-exported at the crate root for ergonomics.
// For advanced configuration types, see the [`x509_source`] module.
#[cfg(feature = "x509-source")]
pub use crate::x509_source::{
    ReconnectConfig, ResourceLimits, X509Source, X509SourceBuilder, X509SourceError,
    X509SourceUpdates,
};
