#![deny(missing_docs)]
#![warn(missing_debug_implementations)]
// #![warn(rust_2018_idioms)]

//! This library provides functions to interact with the SPIRE GRPC APIs as defined in the [SDK](https://github.com/spiffe/spire-api-sdk).

mod proto;

pub mod agent;
pub mod selectors;
