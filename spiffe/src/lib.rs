#![deny(missing_docs)]
#![deny(unsafe_code)]
#![warn(missing_debug_implementations)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![warn(clippy::unwrap_used)]
#![warn(clippy::expect_used)]

//! Rust client library for the [SPIFFE Workload API](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md).
//!
//! This crate provides standards-compliant access to SPIFFE identities and trust material.
//! It allows workloads to fetch and watch SPIFFE-issued X.509 and JWT SVIDs, trust bundles, and
//! related metadata, using strongly typed APIs aligned with the SPIFFE specifications.
//!
//! ## Quick Start
//!
//! For X.509-based workloads, use [`X509Source`] (requires the `x509-source` feature):
//!
//! ```no_run
//! # #[cfg(feature = "x509-source")]
//! # async fn example() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//! use spiffe::{bundle::BundleSource, TrustDomain, X509Source};
//!
//! let source = X509Source::new().await?;
//! let _svid = source.svid()?;
//! let trust_domain = TrustDomain::try_from("example.org")?;
//! let _bundle = source
//!     .bundle_for_trust_domain(&trust_domain)?
//!     .ok_or("missing bundle")?;
//! # Ok(())
//! # }
//! ```
//!
//! For JWT-based workloads, use [`JwtSource`] (requires the `jwt-source` feature):
//!
//! ```no_run
//! # #[cfg(feature = "jwt-source")]
//! # async fn example() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//! use spiffe::{bundle::BundleSource, TrustDomain, JwtSource};
//!
//! let source = JwtSource::new().await?;
//! let _jwt_svid = source.get_jwt_svid(&["service-a", "service-b"]).await?;
//! let trust_domain = TrustDomain::try_from("example.org")?;
//! let _bundle = source
//!     .bundle_for_trust_domain(&trust_domain)?
//!     .ok_or("missing bundle")?;
//! # Ok(())
//! # }
//! ```
//!
//! For direct Workload API access, use [`WorkloadApiClient`] (requires a `workload-api-*` feature):
//!
//! ```no_run
//! # #[cfg(feature = "workload-api")]
//! # async fn example() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//! use spiffe::WorkloadApiClient;
//!
//! let client = WorkloadApiClient::connect_env().await?;
//! let _jwt_svid = client.fetch_jwt_svid(&["audience"], None).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Feature Matrix
//!
//! The crate has **no default features** — everything is opt-in.
//!
//! Most users should enable `x509-source` (for X.509 workloads), `jwt-source` (for JWT workloads),
//! or a `workload-api-*` bundle (for direct Workload API access). The granular features exist to
//! let you minimize dependency surface when you only need X.509 or only need JWT.
//!
//! | Feature | Description |
//! |---------|-------------|
//! | `x509` | X.509 SVID and bundle types + parsing (gates heavy ASN.1/X.509 deps) |
//! | `transport` | Endpoint parsing (no runtime deps) |
//! | `transport-grpc` | gRPC connector |
//! | `jwt` | JWT SVID and bundle types + parsing |
//! | `jwt-verify-rust-crypto` | Offline JWT verification (rust-crypto backend) |
//! | `jwt-verify-aws-lc-rs` | Offline JWT verification (aws-lc-rs backend) |
//! | `logging` | Log-based observability |
//! | `tracing` | Tracing-based observability |
//!
//! ### Workload API bundles
//!
//! These features enable the async Workload API client (`WorkloadApiClient`). Choose the smallest
//! bundle that matches your use case:
//!
//! | Feature | Includes |
//! |---------|----------|
//! | `workload-api-x509` | Workload API client + X.509 support (no JWT) |
//! | `workload-api-jwt` | Workload API client + JWT support (no X.509) |
//! | `workload-api` | Workload API client with both X.509 + JWT support |
//! | `workload-api-full` | Alias/bundle for both X.509 + JWT support (same capability as `workload-api`) |
//!
//! ### Advanced / compositional
//!
//! | Feature | Description |
//! |---------|-------------|
//! | `workload-api-core` | Workload API infrastructure only (transport/proto/client plumbing; no X.509/JWT parsing/types) |
//! | `x509-source` | High-level X.509 watcher/caching built on the Workload API |
//! | `jwt-source` | High-level JWT watcher/caching built on the Workload API |
//!
//! **Notes:**
//!
//! - The `x509` feature gates heavy X.509 parsing dependencies.
//! - For direct Workload API usage, use `workload-api-x509` or `workload-api-jwt` when you only need one,
//!   and `workload-api` (or `workload-api-full`) when you need both.
//!
//! ## X.509
//!
//! ```no_run
//! # #[cfg(feature = "x509-source")]
//! # async fn example() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//! use spiffe::{TrustDomain, X509Source};
//! use spiffe::bundle::BundleSource;
//!
//! let source = X509Source::new().await?;
//! let _svid = source.svid()?;
//! let trust_domain = TrustDomain::try_from("example.org")?;
//! let _bundle = source
//!     .bundle_for_trust_domain(&trust_domain)?
//!     .ok_or("missing bundle")?;
//!
//! # Ok(())
//! # }
//! ```
//!
//! For JWT-based workloads, use [`JwtSource`] (requires the `jwt-source` feature):
//!
//! ```no_run
//! # #[cfg(feature = "jwt-source")]
//! # async fn example() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//! use spiffe::{bundle::BundleSource, TrustDomain, JwtSource};
//!
//! let source = JwtSource::new().await?;
//! let _jwt_svid = source.get_jwt_svid(&["service-a", "service-b"]).await?;
//! let trust_domain = TrustDomain::try_from("example.org")?;
//! let _bundle = source
//!     .bundle_for_trust_domain(&trust_domain)?
//!     .ok_or("missing bundle")?;
//! # Ok(())
//! # }
//! ```
//!
//! For advanced configuration, see the [`x509_source`] and [`jwt_source`] modules.

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

#[cfg(feature = "jwt-source")]
pub mod jwt_source;

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
// Primary types are re-exported at the crate root.
// For advanced configuration types, see the [`x509_source`] module.
#[cfg(feature = "x509-source")]
pub use crate::x509_source::{
    ReconnectConfig as X509ReconnectConfig, ResourceLimits as X509ResourceLimits, X509Source,
    X509SourceBuilder, X509SourceError, X509SourceUpdates,
};

// JWT Source
//
// High-level watcher/caching abstraction for JWT bundles. Available with `jwt-source` feature.
// Primary types are re-exported at the crate root.
// For advanced configuration types, see the [`jwt_source`] module.
#[cfg(feature = "jwt-source")]
pub use crate::jwt_source::{
    JwtSource,
    JwtSourceBuilder,
    JwtSourceError,
    JwtSourceUpdates,
    // Configuration types: both generic and JWT-specific aliases are available.
    // Use the aliased names (`JwtReconnectConfig`, `JwtResourceLimits`) when
    // both X.509 and JWT sources are enabled to avoid ambiguity.
    ReconnectConfig,
    ReconnectConfig as JwtReconnectConfig,
    ResourceLimits,
    ResourceLimits as JwtResourceLimits,
};
