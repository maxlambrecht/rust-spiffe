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
//! ## Quick example (client)
//!
//! ```no_run
//! use spiffe_rustls::{ClientConfigBuilder, ClientConfigOptions};
//! use std::sync::Arc;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let source = spiffe::X509Source::new().await?;
//!
//! let opts = ClientConfigOptions {
//!     trust_domain: "example.org".try_into()?,
//!     authorize_server: Arc::new(|id: &str| {
//!         id == "spiffe://example.org/myservice"
//!     }),
//! };
//!
//! let client_config = ClientConfigBuilder::new(source, opts)
//!     .build()
//!     .await?;
//! # Ok(())
//! # }
//! ```
//!
//! The resulting `ClientConfig` can be used directly with `rustls` or integrated
//! into higher-level libraries such as `tokio-rustls` or `tonic-rustls`.
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

mod crypto;

mod client;
mod error;
mod material;
mod resolve;
mod server;
mod types;
mod verifier;

pub use client::{ClientConfigBuilder, ClientConfigOptions};
pub use error::{Error, Result};
pub use server::{ServerConfigBuilder, ServerConfigOptions};
pub use types::{authorize_any, authorize_exact, AuthorizeSpiffeId};
