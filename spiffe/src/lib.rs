#![deny(missing_docs)]
#![warn(missing_debug_implementations)]

//! This crate provides Rust bindings for the
//! [SPIFFE Workload API](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md).
//!
//! It allows workloads to fetch and watch SPIFFE-issued X.509 and JWT SVIDs,
//! trust bundles, and related metadata, using strongly typed APIs that comply
//! with the SPIFFE standards.
//!
//! The primary entry point for X.509-based workloads is [`X509Source`], which
//! maintains a live connection to the Workload API and automatically tracks
//! SVID and bundle rotation.
//!
//! ## X.509 (recommended)
//!
//! ```no_run
//! use spiffe::{TrustDomain, X509Source};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Connect to the Workload API using SPIFFE_ENDPOINT_SOCKET
//! let source = X509Source::new().await?;
//!
//! // Get the current X.509 context (SVIDs + bundles)
//! let context = source.x509_context()?;
//!
//! // Access the default SVID
//! let svid = context.default_svid().ok_or("missing svid")?;
//!
//! // Inspect the certificate chain and private key
//! let cert_chain = svid.cert_chain();
//! let private_key = svid.private_key();
//!
//! // Access trust bundles by trust domain
//! let trust_domain = TrustDomain::try_from("example.org")?;
//! let bundle = context.bundle_set().get_bundle(&trust_domain).unwrap();
//!
//! # source.shutdown().await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## JWT SVIDs
//!
//! JWT-based identity is supported via [`WorkloadApiClient`] and related types.
//!
//! ```no_run
//! use spiffe::{JwtSvid, WorkloadApiClient};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut client = WorkloadApiClient::default().await?;
//!
//! let audiences = &["service-a"];
//! let jwt_svid = client.fetch_jwt_svid(audiences, None).await?;
//!
//! let claims = jwt_svid.claims();
//! # Ok(())
//! # }
//! ```
//!
//! ## Features
//!
//! - **`spiffe-types`**: Core SPIFFE types (IDs, SVIDs, bundles)
//! - **`workload-api`**: Workload API client and streaming support
//!
//! Most users should enable both features (default).

#[cfg(feature = "spiffe-types")]
pub mod constants;

#[cfg(feature = "spiffe-types")]
pub mod bundle;

#[cfg(feature = "spiffe-types")]
pub mod cert;

#[cfg(feature = "spiffe-types")]
pub mod spiffe_id;

#[cfg(feature = "spiffe-types")]
pub mod svid;

#[cfg(feature = "spiffe-types")]
pub mod error;

#[cfg(feature = "spiffe-types")]
pub mod endpoint;

#[cfg(feature = "workload-api")]
pub mod workload_api;

// -----------------------
// Re-exports
// -----------------------

/// Core SPIFFE types and utilities re-exported for simplified access.
#[cfg(feature = "spiffe-types")]
pub use crate::{
    bundle::jwt::{JwtBundle, JwtBundleError, JwtBundleSet},
    bundle::x509::{X509Bundle, X509BundleError, X509BundleSet},
    bundle::BundleSource,
    spiffe_id::{SpiffeId, SpiffeIdError, TrustDomain},
    svid::jwt::{JwtSvid, JwtSvidError},
    svid::x509::{X509Svid, X509SvidError},
    svid::SvidSource,
};

#[cfg(feature = "workload-api")]
pub use crate::workload_api::client::WorkloadApiClient;

#[cfg(feature = "workload-api")]
pub use crate::workload_api::x509_context::X509Context;

#[cfg(feature = "workload-api")]
pub use crate::workload_api::x509_source::{X509Source, X509SourceBuilder};
