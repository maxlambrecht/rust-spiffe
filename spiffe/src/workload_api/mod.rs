//! A client to interact with the SPIFFE Workload API to fetch X.509 and JWT materials.
//!
//! Higher-level types like [`crate::X509Source`] and [`crate::JwtSource`] provide automatic caching
//! and reconnection. Source construction rejects invalid fixed endpoint syntax and
//! `UNIMPLEMENTED` from the required material RPC before initial synchronization succeeds.
//! Transient transport, provisioning, and rejected response failures remain retriable.
//! After initialization, unsupported RPC statuses retain the existing reconnect policy.
//! Low-level client calls return errors directly and do not apply source retry policy.
//!
//! [`crate::WorkloadApiClient`] provides direct access to one-shot RPCs and streaming updates.

// Generated protobuf bindings.
// Regenerate with: `cargo run -p xtask -- gen spiffe` from the repo root.
#[expect(
    clippy::allow_attributes_without_reason,
    clippy::derive_partial_eq_without_eq,
    clippy::doc_markdown,
    clippy::empty_structs_with_brackets,
    unreachable_pub,
    unused_qualifications,
    unused_results
)]
pub(crate) mod pb {
    pub(crate) mod workload {
        include!("pb/workload.rs");
    }
}
#[cfg(all(test, any(feature = "jwt-source", feature = "x509-source")))]
pub(crate) mod lifecycle_test_support;
#[cfg(all(test, any(feature = "jwt-source", feature = "x509-source")))]
pub(crate) mod startup_test_support;
#[cfg(any(feature = "jwt-source", feature = "x509-source"))]
pub(crate) mod supervisor_common;

pub mod client;
pub mod endpoint;
pub mod error;

#[cfg(feature = "x509")]
pub mod x509_context;

pub use client::InterceptorFn;
pub use client::WorkloadApiClient;
pub use error::WorkloadApiError;

#[cfg(feature = "x509")]
pub use x509_context::X509Context;
