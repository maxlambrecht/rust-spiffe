#![deny(missing_docs)]
#![warn(missing_debug_implementations)]

//! This library provides functions to interact with the SPIRE GRPC APIs as defined in the [SDK](https://github.com/spiffe/spire-api-sdk).

mod proto {
    #![allow(clippy::all)]
    pub mod spire {
        pub mod api {
            pub mod agent {
                pub mod delegatedidentity {
                    pub mod v1 {
                        include!(concat!(
                            env!("OUT_DIR"),
                            "/spire.api.agent.delegatedidentity.v1.rs"
                        ));
                    }
                }
            }

            pub mod types {
                include!(concat!(env!("OUT_DIR"), "/spire.api.types.rs"));
            }
        }
    }
}

pub mod agent;
pub mod selectors;

// Core spire-api crate type re-exported for simplified access.
pub use agent::delegated_identity::{DelegateAttestationRequest, DelegatedIdentityClient};
