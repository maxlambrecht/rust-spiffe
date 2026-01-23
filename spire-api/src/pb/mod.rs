//! Generated protobuf bindings for SPIRE APIs.
//!
//! **This module contains generated code. Do not edit these files manually.**
//!
//! Regenerate with: `cargo run -p xtask -- gen spire-api` from the repo root.
//!
//! ## Lint Suppressions
//!
//! The following lint suppressions are applied to this module because the generated code
//! from `prost`/`tonic-build` does not always conform to our linting standards:
//!
//! - `clippy::all` and `clippy::pedantic`: Generated code may not follow all clippy rules
//! - `missing_docs`: Generated types may lack documentation
//! - `dead_code`, `unused_imports`, etc.: Generated code may include unused items depending on features
//!
//! These suppressions are intentional and scoped to this generated code module only.
#![allow(clippy::all)]
#![allow(missing_docs)]

pub mod spire {
    pub mod api {
        pub mod agent {
            pub mod delegatedidentity {
                pub mod v1 {
                    include!("spire.api.agent.delegatedidentity.v1.rs");
                }
            }
        }
    }
}