//! A client to interact with the SPIFFE Workload API to fetch X.509 and JWT materials.
//!
//! Higher-level types like [`crate::X509Source`] and [`crate::JwtSource`] provide automatic caching
//! and reconnection. [`crate::WorkloadApiClient`] provides direct access to one-shot RPCs and streaming updates.
#![allow(clippy::result_large_err)]

pub(crate) mod pb;
pub(crate) mod supervisor_common;

pub mod client;
pub mod endpoint;
pub mod error;

#[cfg(feature = "x509")]
pub mod x509_context;

pub use client::WorkloadApiClient;
pub use error::WorkloadApiError;

#[cfg(feature = "x509")]
pub use x509_context::X509Context;
