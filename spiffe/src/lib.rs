#![deny(missing_docs)]
#![warn(missing_debug_implementations)]

//! This library provides functions to interact with the [SPIFFE Workload API](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md)
//! to fetch X.509 and JWT SVIDs and Bundles. It also provides types that comply with the [SPIFFE standards](https://github.com/spiffe/spiffe/tree/main/standards).
//!
//! # Examples
//!
//! ```no_run
//! use spiffe::cert::{Certificate, PrivateKey};
//! use spiffe::{
//!     JwtAuthority, JwtBundle, JwtSvid, SpiffeId, TrustDomain, WorkloadApiClient, X509Bundle,
//!     X509BundleSet, X509Context, X509Svid,
//! };
//! use std::convert::TryFrom;
//! use std::error::Error;
//!
//! # async fn some_function() -> Result<(), Box< dyn Error>> {
//!
//! // create a new Workload API client connecting to the provided endpoint socket path
//! let mut client =
//!     WorkloadApiClient::new_from_path("unix:/tmp/spire-agent/api/public.sock").await?;
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
//! // get the X.509 chain of certificates from the SVID
//! let cert_chain: &Vec<Certificate> = x509_svid.cert_chain();
//!
//! // get the private key from the SVID
//! let private_key: &PrivateKey = x509_svid.private_key();
//!
//! // parse a SPIFFE trust domain
//! let trust_domain = TrustDomain::try_from("example.org")?;
//!
//! // get the X.509 bundle associated to the trust domain
//! let x509_bundle: &X509Bundle = x509_bundles.get_bundle(&trust_domain).unwrap();
//!
//! // get the X.509 authorities (public keys) in the bundle
//! let x509_authorities: &Vec<Certificate> = x509_bundle.authorities();
//!
//! // parse a SPIFFE ID
//! let spiffe_id = SpiffeId::try_from("spiffe://example.org/my-service")?;
//!
//! let target_audience = &["service1", "service2"];
//! // fetch a jwt token for the provided SPIFFE-ID and with the target audience `service1.com`
//! let jwt_token = client
//!     .fetch_jwt_token(target_audience, Some(&spiffe_id))
//!     .await?;
//!
//! // fetch the jwt token and parses it as a `JwtSvid`
//! let jwt_svid = client
//!     .fetch_jwt_svid(target_audience, Some(&spiffe_id))
//!     .await?;
//!
//! // fetch a set of jwt bundles (public keys for validating jwt token)
//! let jwt_bundles_set = client.fetch_jwt_bundles().await?;
//!
//! // get the JWT bundle associated to the trust domain
//! let jwt_bundle: &JwtBundle = jwt_bundles_set.get_bundle(&trust_domain).unwrap();
//!
//! // get the JWT authorities (public keys) in the bundle
//! let jwt_authority: &JwtAuthority = jwt_bundle.find_jwt_authority("a_key_id").unwrap();
//!
//! // parse a `JwtSvid` validating the token signature with a JWT bundle source.
//! let validated_jwt_svid =
//!     JwtSvid::parse_and_validate(&jwt_token, &jwt_bundles_set, &["service1.com"])?;
//!
//! # Ok(())
//! # }
//! ```

#[cfg(feature = "spiffe-types")]
pub mod constants;

#[cfg(feature = "spiffe-types")]
pub mod bundle;

#[cfg(feature = "spiffe-types")]
pub mod cert;

#[cfg(feature = "spiffe-types")]
pub mod spiffe_id;

#[cfg(feature = "spiffe-types")]
pub mod svid;

#[cfg(feature = "spiffe-types")]
pub mod error;

#[cfg(feature = "spiffe-types")]
pub mod endpoint;

#[cfg(feature = "workload-api")]
pub(crate) mod proto;

#[cfg(feature = "workload-api")]
pub mod workload_api;

// Core SPIFFE types and utilities re-exported for simplified access.
pub use bundle::jwt::{JwtAuthority, JwtBundle, JwtBundleError, JwtBundleSet};
pub use bundle::x509::{X509Bundle, X509BundleError, X509BundleSet};
pub use bundle::BundleSource;
pub use spiffe_id::{SpiffeId, SpiffeIdError, TrustDomain};
pub use svid::jwt::{JwtSvid, JwtSvidError};
pub use svid::x509::{X509Svid, X509SvidError};
pub use svid::SvidSource;

#[cfg(feature = "workload-api")]
pub use workload_api::client::WorkloadApiClient;
#[cfg(feature = "workload-api")]
pub use workload_api::x509_context::X509Context;
#[cfg(feature = "workload-api")]
pub use workload_api::x509_source::{X509Source, X509SourceBuilder};
