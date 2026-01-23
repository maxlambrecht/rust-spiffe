//! Agent API
//!
//! Provides the following APIs:
//! - `delegated_identity`: For managing delegated identities.
//! - `debug`: (Not yet implemented).
//!
//! Access these APIs via the `admin_socket_path` in the [agent configuration file](https://spiffe.io/docs/latest/deploying/spire_agent/#agent-configuration-file).

// Error types include protobuf-generated types which can be large. Boxing would change
// the public API, so we allow this lint here.
#![allow(clippy::result_large_err)]
pub mod delegated_identity;
