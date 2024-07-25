#![deny(missing_docs)]
#![warn(missing_debug_implementations)]

//! This library provides functions to interact with the SPIRE GRPC APIs as defined in the [SDK](https://github.com/spiffe/spire-api-sdk).

mod proto;

pub mod agent;
pub mod selectors;

// Core spire-api crate type re-exported for simplified access.
pub use agent::delegated_identity::{DelegatedIdentityClient, DelegateAttestationRequest};
