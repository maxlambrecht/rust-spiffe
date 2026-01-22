#![deny(missing_docs)]
#![deny(unsafe_code)]
#![warn(missing_debug_implementations)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

//! # spiffe-rustls
//!
//! `spiffe-rustls` integrates [`rustls`] with SPIFFE/SPIRE using a live
//! [`spiffe::X509Source`] (SPIFFE Workload API).
//!
//! It provides builders for [`rustls::ClientConfig`] and
//! [`rustls::ServerConfig`] that are backed by an `X509Source`. When the SPIRE
//! agent rotates X.509 SVIDs or trust bundles, **new TLS handshakes automatically
//! use the updated material**, without restarting the application.
//!
//! The crate focuses on TLS authentication and **connection-level authorization
//! via SPIFFE IDs**, while delegating all cryptography and TLS mechanics to
//! `rustls`.
//!
//! When SPIFFE federation is configured, the crate automatically selects the correct
//! trust domain bundle based on the peer's SPIFFE ID. Authorization is applied **after**
//! cryptographic verification succeeds.
//!
//! ## Feature flags
//!
//! Exactly **one** `rustls` crypto provider must be enabled:
//!
//! * `ring` (default)
//! * `aws-lc-rs`
//!
//! Enabling more than one provider results in a compile-time error.

#[cfg(all(feature = "ring", feature = "aws-lc-rs"))]
compile_error!("Enable only one crypto provider feature: `ring` or `aws-lc-rs`.");

#[cfg(not(any(feature = "ring", feature = "aws-lc-rs")))]
compile_error!("Enable one crypto provider feature: `ring` (default) or `aws-lc-rs`.");

pub mod authorizer;

mod crypto;
mod error;
mod material;

mod observability;
mod prelude;

mod client;
mod policy;
mod resolve;
mod server;
mod verifier;

// Public re-exports
pub use authorizer::{any, exact, trust_domains, Authorizer};
pub use client::ClientConfigBuilder;
pub use error::{Error, Result};
pub use policy::TrustDomainPolicy;
pub use policy::TrustDomainPolicy::{AllowList, AnyInBundleSet, LocalOnly};
pub use server::ServerConfigBuilder;
pub use spiffe::{SpiffeId, TrustDomain};

/// Constructor for the mTLS client builder.
///
/// Creates a client builder with default settings (accepts any SPIFFE ID, uses all bundles from the Workload API).
///
/// # Examples
///
/// ```no_run
/// use spiffe_rustls::{authorizer, mtls_client};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let source = spiffe::X509Source::new().await?;
///
/// let client_config = mtls_client(source)
///     .authorize(authorizer::exact([
///         "spiffe://example.org/myservice",
///     ])?)
///     .build()?;
/// # Ok(())
/// # }
/// ```
pub fn mtls_client(source: spiffe::X509Source) -> ClientConfigBuilder {
    ClientConfigBuilder::new(source)
}

/// Constructor for the mTLS server builder.
///
/// Creates a server builder with default settings (accepts any SPIFFE ID, uses all bundles from the Workload API).
///
/// # Examples
///
/// ```no_run
/// use spiffe_rustls::{authorizer, mtls_server};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let source = spiffe::X509Source::new().await?;
///
/// let server_config = mtls_server(source)
///     .authorize(authorizer::trust_domains(["example.org"])?)
///     .build()?;
/// # Ok(())
/// # }
/// ```
pub fn mtls_server(source: spiffe::X509Source) -> ServerConfigBuilder {
    ServerConfigBuilder::new(source)
}
