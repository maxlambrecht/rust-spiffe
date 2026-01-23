//! Client bindings for SPIRE gRPC APIs.
//!
//! Provides wrappers around SPIRE's gRPC APIs (generated from protobuf)
//! with strongly-typed request helpers.
//!
//! SPIRE exposes multiple gRPC APIs over a local endpoint (typically a Unix domain socket).
//! High-level clients accept a pre-built `tonic::transport::Channel` for
//! explicit transport configuration (timeouts, TLS, interceptors, etc).
//!
//! ## Quick start
//!
//! ```no_run
//! use spire_api::{DelegatedIdentityClient, DelegateAttestationRequest};
//! use spire_api::selectors;
//!
//! # async fn demo() -> Result<(), spire_api::DelegatedIdentityError> {
//! // Connect using the SPIRE_ADMIN_ENDPOINT_SOCKET environment variable
//! let client = DelegatedIdentityClient::connect_env().await?;
//!
//! // Or connect to a specific endpoint
//! // let client = DelegatedIdentityClient::connect_to("unix:///tmp/spire-agent/public/admin.sock").await?;
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

#![cfg_attr(
    test,
    expect(unused_crate_dependencies, reason = "used in the integration tests")
)]

/// Generated protobuf bindings for SPIRE APIs.
///
/// **This module contains generated code. Do not edit these files manually.**
///
/// Regenerate with: `cargo run -p xtask -- gen spire-api` from the repo root.
///
/// ## Lint Suppressions
///
/// The following lint suppressions are applied to this module because the generated code
/// from `prost`/`tonic-build` does not always conform to our linting standards:
///
/// - `clippy::all` and `clippy::pedantic`: Generated code may not follow all clippy rules
/// - `missing_docs`: Generated types may lack documentation
/// - `dead_code`, `unused_imports`, etc.: Generated code may include unused items depending on features
///
/// These suppressions are intentional and scoped to this generated code module only.
#[expect(
    clippy::allow_attributes_without_reason,
    clippy::derive_partial_eq_without_eq,
    clippy::doc_lazy_continuation,
    clippy::doc_markdown,
    clippy::empty_structs_with_brackets,
    clippy::missing_const_for_fn,
    clippy::missing_errors_doc,
    clippy::too_long_first_doc_paragraph,
    missing_docs,
    unused_qualifications,
    unused_results
)]
pub mod pb {
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

/// Common re-exports.
pub mod prelude {
    /// Common imports for SPIRE client usage.
    pub use crate::agent::delegated_identity::{
        DelegateAttestationRequest, DelegatedIdentityClient, DelegatedIdentityError,
    };
    pub use crate::selectors;
}

pub use agent::delegated_identity::{
    DelegateAttestationRequest, DelegatedIdentityClient, DelegatedIdentityError,
};
