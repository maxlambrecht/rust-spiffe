//! A client to interact with the SPIFFE Workload API to fetch X.509 and JWT materials.
//!
//! Most users should prefer higher-level types like [`crate::X509Source`] for X.509 workloads,
//! but [`crate::WorkloadApiClient`] provides direct access to one-shot RPCs and streaming updates.
//!
//! # Example
//!
//! ```no_run
//! # #[cfg(feature = "workload-api")]
//! # async fn example() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//! use spiffe::WorkloadApiClient;
//!
//! // Connect using SPIFFE_ENDPOINT_SOCKET, e.g.:
//! // export SPIFFE_ENDPOINT_SOCKET="unix:/tmp/spire-agent/public/api.sock"
//! let client = WorkloadApiClient::connect_env().await?;
//!
//! let audience = &["service1", "service2"];
//!
//! // Fetch a JWT token (string) for the default identity.
//! let _jwt_token = client.fetch_jwt_token(audience, None).await?;
//!
//! // Fetch and parse a JWT-SVID for the default identity.
//! let _jwt_svid = client.fetch_jwt_svid(audience, None).await?;
//!
//! // Fetch JWT bundles (authorities for validating JWT-SVIDs).
//! let _jwt_bundles = client.fetch_jwt_bundles().await?;
//!
//! // Fetch the default X.509 SVID.
//! let _x509_svid = client.fetch_x509_svid().await?;
//!
//! // Fetch X.509 bundles.
//! let _x509_bundles = client.fetch_x509_bundles().await?;
//!
//! // Fetch the full X.509 context (SVIDs + bundles).
//! let _x509_context = client.fetch_x509_context().await?;
//!
//! # Ok(())
//! # }
//! ```
#![allow(clippy::result_large_err)]

pub(crate) mod pb;

pub mod client;
pub mod endpoint;
pub mod error;
pub mod x509_context;
pub mod x509_source;

pub use client::WorkloadApiClient;
pub use error::WorkloadApiError;
pub use x509_context::X509Context;
pub use x509_source::{
    LimitKind, MetricsErrorKind, MetricsRecorder, ResourceLimits, X509Source, X509SourceBuilder,
    X509SourceUpdates, UNLIMITED,
};
