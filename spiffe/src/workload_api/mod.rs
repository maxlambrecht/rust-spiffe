//! A client to interact with the Workload API to fetch X.509 and JWT materials.
//!
//! # Examples
//!
//! ```no_run
//!
//! use std::error::Error;
//! use spiffe::WorkloadApiClient;
//!
//! use spiffe::X509Svid;
//! use spiffe::X509BundleSet;
//! use spiffe::X509Context;
//!
//! # async fn example() -> Result<(), Box< dyn Error>> {
//!
//! // create a new Workload API client connecting to an socket path defined by the environment variable:
//! // `export SPIFFE_ENDPOINT_SOCKET = "unix:/tmp/spire-agent/api/public.sock"`
//! let mut client = WorkloadApiClient::default().await?;
//!
//! let target_audience = &["service1", "service2"];
//! // fetch a jwt token for the default identity with target audience
//! let jwt_token = client.fetch_jwt_token(target_audience, None).await?;
//!
//! // fetch the jwt token for the default identity and parses it as a `JwtSvid`
//! let jwt_svid = client.fetch_jwt_svid(target_audience, None).await?;
//!
//! // fetch a set of jwt bundles (public keys for validating jwt token)
//! let jwt_bundles = client.fetch_jwt_bundles().await?;
//!
//! // fetch the default X.509 SVID
//! let x509_svid: X509Svid = client.fetch_x509_svid().await?;
//!
//! // fetch a set of X.509 bundles (X.509 public key authorities)
//! let x509_bundles: X509BundleSet = client.fetch_x509_bundles().await?;
//!
//! // fetch all the X.509 materials (SVIDs and bundles)
//! let x509_context: X509Context = client.fetch_x509_context().await?;
//!
//! # Ok(())
//! # }
//! ```
pub mod client;
pub mod x509_context;
pub mod x509_source;
