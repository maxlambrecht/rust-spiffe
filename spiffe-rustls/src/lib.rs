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
//! ## Federation
//!
//! When SPIFFE federation is configured, the Workload API delivers trust bundles
//! for multiple trust domains. `spiffe-rustls` automatically handles this:
//!
//! * The verifier extracts the peer's SPIFFE ID from their certificate
//! * It derives the trust domain from that SPIFFE ID
//! * It selects the correct root certificate bundle from the bundle set
//! * Certificate verification proceeds using the selected bundle
//!
//! **No federation-specific configuration is required.** Federation works
//! automatically whenever the Workload API provides bundles for multiple trust
//! domains. You can optionally restrict which trust domains are trusted using
//! [`TrustDomainPolicy`], but this is purely a defense-in-depth mechanism.
//! Policy variants (`AnyInBundleSet`, `AllowList`, `LocalOnly`) are re-exported
//! at the crate root for convenience.
//!
//! ## Security Model
//!
//! The crate follows a strict security model to ensure cryptographic verification
//! is never bypassed:
//!
//! 1. **SPIFFE ID extraction (pre-verification)**: The peer's SPIFFE ID is extracted
//!    from the certificate's URI SAN **before** cryptographic verification. This is
//!    safe because it is **only used to select the trust domain's root certificate bundle**.
//!    The extracted SPIFFE ID has no security impact at this stage.
//!
//! 2. **Cryptographic verification**: Certificate verification (signature validation,
//!    chain validation, expiration checks) is performed by `rustls`/`webpki` using the
//!    selected root certificate bundle. This is the authoritative security boundary.
//!
//! 3. **Authorization (post-verification)**: Authorization based on SPIFFE ID is applied
//!    **only after** cryptographic verification succeeds. If authorization fails, the
//!    handshake is rejected.
//!
//! **Failure modes**: If the trust domain's bundle is absent from the bundle set, or if
//! the trust domain is rejected by policy, certificate verification fails and the handshake
//! is rejected. This ensures that only cryptographically verified peers from allowed trust
//! domains can establish connections.
//!
//! ## Authorization
//!
//! Authorization is performed **after** cryptographic verification succeeds. The
//! crate provides a strongly-typed [`authorizer::Authorizer`] trait for implementing
//! authorization policies.
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

// Crate-internal modules
mod client;
mod crypto;
mod error;
mod material;

mod observability;
mod prelude;

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

/// Convenience constructor for the mTLS client builder.
///
/// This creates a client builder with default settings:
/// - Authorization: accepts any SPIFFE ID (authentication only)
/// - Trust domain policy: `AnyInBundleSet` (uses all bundles from the Workload API)
///
/// # Examples
///
/// ```no_run
/// use spiffe_rustls::{authorizer, mtls_client};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let source = spiffe::X509Source::new().await?;
///
/// // Using a convenience constructor - pass string literals directly
/// let client_config = mtls_client(source.clone())
///     .authorize(authorizer::exact([
///         "spiffe://example.org/myservice",
///         "spiffe://example.org/myservice2",
///     ])?)
///     .build()?;
///
/// // Using a closure
/// let client_config = mtls_client(source.clone())
///     .authorize(|id: &spiffe::SpiffeId| id.path().starts_with("/api/"))
///     .build()?;
///
/// // Using the Any authorizer (default)
/// let client_config = mtls_client(source)
///     .authorize(authorizer::any())
///     .build()?;
/// # Ok(())
/// # }
/// ```
pub fn mtls_client(source: std::sync::Arc<spiffe::X509Source>) -> ClientConfigBuilder {
    ClientConfigBuilder::new(source)
}

/// Convenience constructor for the mTLS server builder.
///
/// This creates a server builder with default settings:
/// - Authorization: accepts any SPIFFE ID (authentication only)
/// - Trust domain policy: `AnyInBundleSet` (uses all bundles from the Workload API)
///
/// # Examples
///
/// ```no_run
/// use spiffe_rustls::{authorizer, mtls_server};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let source = spiffe::X509Source::new().await?;
///
/// // Using a convenience constructor - pass string literals directly
/// let server_config = mtls_server(source.clone())
///     .authorize(authorizer::trust_domains([
///         "example.org",
///     ])?)
///     .build()?;
///
/// // Using a closure
/// let server_config = mtls_server(source.clone())
///     .authorize(|id: &spiffe::SpiffeId| id.path().starts_with("/api/"))
///     .build()?;
///
/// // Using the Any authorizer (default)
/// let server_config = mtls_server(source)
///     .authorize(authorizer::any())
///     .build()?;
/// # Ok(())
/// # }
/// ```
pub fn mtls_server(source: std::sync::Arc<spiffe::X509Source>) -> ServerConfigBuilder {
    ServerConfigBuilder::new(source)
}
