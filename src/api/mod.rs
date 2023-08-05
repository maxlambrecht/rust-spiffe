//! This library provides functions to interact with the [SPIFFE APIs]
//!
//! The functionality is broken by it's respective API definitions.
//! Currently the 2 implemented APIs are: 
//! - [Workload](https://github.com/spiffe/spiffe/blob/main/standards/workloadapi.proto)
//! - [DelegatedIdentity](https://github.com/spiffe/spire-api-sdk/blob/main/proto/spire/api/agent/delegatedidentity/v1/delegatedidentity.proto)

#[cfg(feature = "tonic")]
pub mod delegated_identity;