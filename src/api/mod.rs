//! This module provides an API surface to interact with the SPIRE APIs.
//! 
//! As of right now the implements APIs are: 
//! - Workload
//! - DelegatedIdentity
//! 
//! 
//! Workload Identity API should be used when an application is acting on behalf of itself,
//! fefching SVIDs and Bundles for its own identity.
//! 
//! DelegatedIdentity API should be used when an application is acting on behalf of another, 
//! or potentially many others.


pub mod delegated_identity;
