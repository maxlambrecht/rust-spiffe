#![deny(missing_docs)]
#![deny(unsafe_code)]
#![warn(missing_debug_implementations)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

//! Rust client bindings for SPIRE gRPC APIs.
//!
//! This crate provides ergonomic wrappers around SPIRE's gRPC APIs (generated from protobuf)
//! with strongly-typed request helpers.
//!
//! ## Endpoints and transport
//!
//! SPIRE exposes multiple gRPC APIs (e.g. the Agent API) over a local endpoint. In most
//! deployments this is a Unix domain socket.
//!
//! The high-level clients in this crate typically accept a pre-built `tonic::transport::Channel`.
//! This keeps transport configuration explicit and composable (timeouts, TLS, interceptors, etc).
//!
//! ## Quick start
//!
//! ```no_run
//! use spire_api::{DelegatedIdentityClient, DelegateAttestationRequest};
//! use spire_api::selectors;
//!
//! # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! // Build a tonic Channel (example shown for a standard TCP URI).
//! // For Unix domain sockets, build the Channel using a custom connector.
//! let channel = tonic::transport::Channel::from_static("http://127.0.0.1:8081")
//!     .connect()
//!     .await?;
//!
//! let client = DelegatedIdentityClient::new(channel)?;
//!
//! let svid = client
//!     .fetch_x509_svid(DelegateAttestationRequest::Selectors(vec![
//!         selectors::Selector::Unix(selectors::Unix::Uid(1000)),
//!     ]))
//!     .await?;
//!
//! println!("SPIFFE ID: {}", svid.spiffe_id());
//! # Ok(())
//! # }
//! ```
//!
//! ## Generated protobuf types
//!
//! Protobuf-generated types are available under [`pb`]. Most users should not need to use these
//! directly, but they are exposed for advanced use-cases.

/// Protobuf-generated types for SPIRE APIs.
///
/// These bindings are generated from SPIRE's protobuf definitions and are considered a
/// lower-level interface than the high-level clients in this crate.
pub mod pb {
    #[allow(
        missing_docs,
        clippy::all,
        clippy::pedantic,
        clippy::module_name_repetitions,
        dead_code,
        non_camel_case_types,
        non_snake_case,
        non_upper_case_globals,
        unused_imports,
        unused_qualifications
    )]

    pub mod spire {
        pub mod api {
            pub mod agent {
                pub mod delegatedidentity {
                    pub mod v1 {
                        include!("pb/spire.api.agent.delegatedidentity.v1.rs");
                    }
                }
            }

            pub mod types {
                include!("pb/spire.api.types.rs");
            }
        }
    }
}

/// SPIRE Agent API clients.
pub mod agent;

/// Selector types used by SPIRE APIs.
pub mod selectors;

/// Common re-exports for convenience.
///
/// This is intentionally small; prefer importing types from their modules for clarity.
pub mod prelude {
    /// Common imports for SPIRE client usage.
    pub use crate::agent::delegated_identity::{
        DelegateAttestationRequest, DelegatedIdentityClient,
    };
    pub use crate::selectors;
}

// Re-exports (top-level convenience)
pub use agent::delegated_identity::{DelegateAttestationRequest, DelegatedIdentityClient};
