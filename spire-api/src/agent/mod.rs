//! Agent API
//! 
//! The agent API consists of APIs:
//! - delegated_identity
//! - debug (not implemented)
//! 
//! # Note
//! Both of these APIs must be accesed via the admin_socket_path which can be set 
//! in the [agent configuration file](https://spiffe.io/docs/latest/deploying/spire_agent/#agent-configuration-file).
//! 
//! 

pub mod delegated_identity;