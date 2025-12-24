#![deny(missing_docs)]
#![warn(missing_debug_implementations)]

//! Rust client bindings for SPIRE gRPC APIs.

mod pb {
    #![allow(clippy::all)]
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

pub mod agent;
pub mod selectors;

// Re-exports
pub use agent::delegated_identity::{DelegateAttestationRequest, DelegatedIdentityClient};
