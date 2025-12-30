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
//! For X.509-based workloads, the primary entry point is [`X509Source`] (requires
//! the `workload-api` feature). It maintains a cached view of the latest X.509
//! materials and automatically tracks SVID and bundle rotation.
//!
//! ## X.509 (recommended)
//!
//! ```no_run
//! # #[cfg(feature = "workload-api")]
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
//! # #[cfg(feature = "workload-api")]
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
pub mod cert;
pub mod constants;
pub mod endpoint;
pub mod spiffe_id;
pub mod svid;

mod observability;
mod prelude;

#[cfg(feature = "transport")]
pub mod transport;

#[cfg(all(feature = "workload-api", feature = "transport"))]
pub mod workload_api;

// Core identifiers
pub use crate::spiffe_id::{SpiffeId, SpiffeIdError, TrustDomain};

// SVIDs
pub use crate::svid::jwt::{JwtSvid, JwtSvidError};
pub use crate::svid::x509::{X509Svid, X509SvidError};

// Bundles
pub use crate::bundle::jwt::{JwtBundle, JwtBundleError, JwtBundleSet};
pub use crate::bundle::x509::{X509Bundle, X509BundleError, X509BundleSet};

// Workload API high-level surfaces
#[cfg(all(feature = "workload-api", feature = "transport"))]
pub use crate::workload_api::{
    error::WorkloadApiError, LimitKind, MetricsErrorKind, MetricsRecorder, ResourceLimits,
    WorkloadApiClient, X509Context, X509Source, X509SourceBuilder, X509SourceUpdates,
};

#[cfg(all(feature = "workload-api", feature = "transport"))]
pub use crate::endpoint::{Endpoint, EndpointError};
