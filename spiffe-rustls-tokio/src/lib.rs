#![deny(missing_docs)]
#![deny(unsafe_code)]
#![warn(missing_debug_implementations)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

//! # spiffe-rustls-tokio
//!
//! Tokio-native accept/connect helpers for [spiffe-rustls](https://docs.rs/spiffe-rustls) configs.
//!
//! Integrates `tokio-rustls` with automatic peer SPIFFE ID extraction. Provides `TlsAcceptor` and
//! `TlsConnector` that return `(TlsStream, PeerIdentity)` after successful handshakes. Runtime-agnostic
//! TLS configuration remains in `spiffe-rustls`.
//!
//! ## Example
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use spiffe::X509Source;
//! use spiffe_rustls::{authorizer, mtls_client};
//! use spiffe_rustls_tokio::TlsConnector;
//! use std::sync::Arc;
//!
//! let source = X509Source::new().await?;
//! let client_config = mtls_client(source)
//!     .authorize(authorizer::any())
//!     .build()?;
//!
//! let connector = TlsConnector::new(Arc::new(client_config));
//! # Ok(())
//! # }
//! ```

mod acceptor;
mod connector;
mod error;
mod identity;

pub use acceptor::TlsAcceptor;
pub use connector::TlsConnector;
pub use error::Error;
pub use identity::PeerIdentity;
