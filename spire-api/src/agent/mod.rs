//! Agent API
//!
//! Consists of the following APIs:
//! - `delegated_identity`: For managing delegated identities.
//! - `debug`: (Not yet implemented).
//!
//! # Note
//! Access these APIs via the `admin_socket_path` in the [agent configuration file](https://spiffe.io/docs/latest/deploying/spire_agent/#agent-configuration-file).
pub mod delegated_identity;
