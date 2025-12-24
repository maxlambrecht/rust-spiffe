//! rustls integration for SPIFFE `X509Source` (SPIRE Workload API).
//!
//! This crate builds `rustls::ClientConfig` and `rustls::ServerConfig` that use an always-up-to-date
//! [`spiffe::X509Source`] for:
//! - the local X.509 SVID (certificate + private key)
//! - the trust bundle for peer verification (by trust domain)
//!
//! Peer authorization is performed using a user-provided callback over the peer SPIFFE ID
//! (URI SAN, e.g. `spiffe://example.org/myservice`).
//!
//! See `examples/mtls_tcp_client` and `examples/mtls_tcp_server` for complete runnable examples.

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
pub use types::{AuthorizeSpiffeId, authorize_any, authorize_exact};
