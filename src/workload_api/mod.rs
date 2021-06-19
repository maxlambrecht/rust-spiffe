//! A client to interact with the Workload API to fetch X.509 and JWT materials.
//!
//! # Examples
//!
//! ```no_run
//! 
//! use std::error::Error;
//! use spiffe::workload_api::client::WorkloadApiClient;
//!
//! use spiffe::svid::x509::X509Svid;
//! use spiffe::bundle::x509::X509BundleSet;
//! use spiffe::workload_api::x509_context::X509Context;
//!
//! # fn main() -> Result<(), Box< dyn Error>> {
//!
//! // create a new Workload API client connecting to an socket path defined by the environment variable:
//! // `export SPIFFE_ENDPOINT_SOCKET = "unix:/tmp/spire-agent/api/public.sock"`
//! let client = WorkloadApiClient::default()?;
//!
//! let target_audience = &["service1", "service2"];
//! // fetch a jwt token for the default identity with target audience
//! let jwt_token = client.fetch_jwt_token(target_audience, None)?;
//!
//! // fetch the jwt token for the default identity and parses it as a `JwtSvid`
//! let jwt_svid = client.fetch_jwt_svid(target_audience, None)?;
//!
//! // fetch a set of jwt bundles (public keys for validating jwt token)
//! let jwt_bundles = client.fetch_jwt_bundles()?;
//!
//! // fetch the default X.509 SVID
//! let x509_svid: X509Svid = client.fetch_x509_svid()?;
//!
//! // fetch a set of X.509 bundles (X.509 public key authorities)
//! let x509_bundles: X509BundleSet = client.fetch_x509_bundles()?;
//!
//! // fetch all the X.509 materials (SVIDs and bundles)
//! let x509_context: X509Context = client.fetch_x509_context()?;
//!
//! # Ok(())
//! # }
//! ```
pub mod address;
pub mod client;
pub mod x509_context;
