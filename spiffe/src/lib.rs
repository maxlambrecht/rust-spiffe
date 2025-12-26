#![deny(missing_docs)]
#![deny(unsafe_code)]
#![warn(missing_debug_implementations)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

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
//! # #[cfg(feature = "workload-api")]
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use spiffe::{TrustDomain, X509Source};
//!
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
//! let _bundle = context.bundle_set().bundle_for(&trust_domain).unwrap();
//!
//! source.shutdown().await;
//! # Ok(())
//! # }
//! ```
//!
//! ## JWT SVIDs
//!
//! ```no_run
//! # #[cfg(feature = "workload-api")]
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use spiffe::WorkloadApiClient;
//!
//! let client = WorkloadApiClient::connect_env().await?;
//!
//! let audiences = &["service-a"];
//! let jwt_svid = client.fetch_jwt_svid(audiences, None).await?;
//!
//! let claims = jwt_svid.claims();
//! # Ok(())
//! # }
//! ```

pub mod bundle;
pub mod cert;
pub mod constants;
pub mod endpoint;
pub mod error;
pub mod spiffe_id;
pub mod svid;

#[cfg(feature = "workload-api")]
pub mod workload_api;

#[cfg(feature = "grpc")]
pub mod grpc;

// Re-exports
pub use crate::{
    bundle::jwt::{JwtBundle, JwtBundleError, JwtBundleSet},
    bundle::x509::{X509Bundle, X509BundleError, X509BundleSet},
    bundle::BundleSource,
    endpoint::{Endpoint, EndpointError},
    spiffe_id::{SpiffeId, SpiffeIdError, TrustDomain},
    svid::jwt::{JwtSvid, JwtSvidError},
    svid::x509::{X509Svid, X509SvidError},
    svid::SvidSource,
};

#[cfg(feature = "workload-api")]
pub use crate::workload_api::{
    client::WorkloadApiClient,
    x509_context::X509Context,
    x509_source::{X509Source, X509SourceBuilder},
};
