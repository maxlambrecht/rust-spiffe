//! A Workload API client implementation to fetch X.509 and JWT materials.
//! # Examples
//!
//! ```no_run
//! use spiffe::workload_api::client::WorkloadApiClient;
//! use std::error::Error;
//!
//! use spiffe::bundle::x509::X509BundleSet;
//! use spiffe::svid::x509::X509Svid;
//! use spiffe::workload_api::x509_context::X509Context;
//!
//! # fn main() -> Result<(), Box< dyn Error>> {
//!
//! let client = WorkloadApiClient::new("unix:/tmp/spire-agent/public/api.sock")?;
//!
//! let target_audience = &["service1", "service2"];
//! // fetch a jwt token for the default identity with the target audience
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
//! // fetch a stream of X.509 materials (SVIDS and bundles)
//! let x509_context_stream = client.watch_x509_context_stream()?;
//!
//! # Ok(())
//! # }
//! ```

use std::str::FromStr;

use futures::executor::block_on;
use futures::StreamExt;
use grpcio::{CallOption, ChannelBuilder, EnvBuilder};
use thiserror::Error;

use crate::bundle::jwt::{JwtBundle, JwtBundleError, JwtBundleSet};
use crate::bundle::x509::{X509Bundle, X509BundleError, X509BundleSet};
use crate::proto::workload::{
    JWTBundlesRequest, JWTBundlesResponse, JWTSVIDRequest, JWTSVIDResponse, ValidateJWTSVIDRequest,
    ValidateJWTSVIDResponse, X509BundlesRequest, X509BundlesResponse, X509SVIDRequest,
    X509SVIDResponse,
};
use crate::proto::workload_grpc;
use crate::proto::workload_grpc::SpiffeWorkloadApiClient;
use crate::spiffe_id::{SpiffeId, SpiffeIdError, TrustDomain};
use crate::svid::jwt::{JwtSvid, JwtSvidError};
use crate::svid::x509::{X509Svid, X509SvidError};
use crate::workload_api::address::{
    get_default_socket_path, validate_socket_path, SocketPathError,
};
use crate::workload_api::x509_context::X509Context;
use futures::Stream;
use std::convert::TryFrom;
use std::sync::Arc;

/// The default SVID is the first in the list of SVIDs returned by the Workload API.
pub const DEFAULT_SVID: usize = 0;

const SPIFFE_HEADER_KEY: &str = "workload.spiffe.io";
const SPIFFE_HEADER_VALUE: &str = "true";

/// This type represents a client to interact with the Workload API.
///
/// Supports one-shot calls for X.509 and JWT SVIDs and bundles.
///
/// NOTE: It will support 'watch-for-updates' methods on later versions.
#[allow(missing_debug_implementations)]
pub struct WorkloadApiClient {
    client: workload_grpc::SpiffeWorkloadApiClient,
}

/// An error that may arise fetching X.509 and JWT materials with the [`WorkloadApiClient`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ClientError {
    /// The environment variable `SPIFFE_ENDPOINT_SOCKET` is not set.
    #[error("endpoint socket address environment variable is not set")]
    MissingEndpointSocketPath,

    /// The Workload API returned an empty response.
    #[error("empty response from the Workload API")]
    EmptyResponse,

    /// The configured Endpoint Socket path is not valid.
    #[error("invalid endpoint socket path")]
    EndpointSocketPath(#[from] SocketPathError),

    /// The Workload API response cannot be parsed as a [`X509Svid`].
    #[error("cannot process X509Svid response")]
    InvalidX509Svid(#[from] X509SvidError),

    /// The Workload API response cannot be parsed as a [`JwtSvid`].
    #[error("cannot process X509Svid response")]
    InvalidJwtSvid(#[from] JwtSvidError),

    /// The Workload API response cannot be parsed as a [`X509Bundle`].
    #[error("cannot process X509Bundle response")]
    InvalidX509Bundle(#[from] X509BundleError),

    /// The Workload API response cannot be parsed as a [`JwtBundle`].
    #[error("cannot process JwtBundle response")]
    InvalidJwtBundle(#[from] JwtBundleError),

    /// The Workload API response contains an invalid [`TrustDomain`]
    #[error("trust domain in bundles response is invalid")]
    InvalidTrustDomain(#[from] SpiffeIdError),

    /// Error returned by the GRPC library, when there is an error connecting to the Workload API.
    #[error("error response from the Workload API: {0}")]
    Grpc(#[from] grpcio::Error),
}

impl WorkloadApiClient {
    /// Creates a new `WorkloadApiClient` with the given Workload API socket path.
    ///
    /// # Arguments
    ///
    /// * `socket_path` - The endpoint socket path where the Workload API is listening for requests,
    /// e.g. `unix:/tmp/spire-agent/public/api.sock`.
    ///
    /// # Errors
    ///
    /// The function returns a variant of [`ClientError`] if the provided socket path is not valid.
    pub fn new(socket_path: &str) -> Result<Self, ClientError> {
        validate_socket_path(socket_path)?;

        let env = Arc::new(EnvBuilder::new().build());
        let channel = ChannelBuilder::new(env).connect(socket_path);
        let client = SpiffeWorkloadApiClient::new(channel);

        Ok(WorkloadApiClient { client })
    }

    /// Creates a new `WorkloadApiClient` using the default socket endpoint address.
    ///
    /// Requires that the environment variable `SPIFFE_ENDPOINT_SOCKET` be set with
    /// the path to the Workload API endpoint socket.
    ///
    /// # Errors
    ///
    /// The function returns a variant of [`ClientError`] if environment variable is not set or if
    /// the provided socket path is not valid.
    pub fn default() -> Result<Self, ClientError> {
        let socket_path = match get_default_socket_path() {
            None => return Err(ClientError::MissingEndpointSocketPath),
            Some(s) => s,
        };
        Self::new(socket_path.as_str())
    }

    /// Fetches the default [`X509Svid`], i.e. the first in the list returned by the Workload API.
    ///
    /// # Errors
    ///
    /// The function returns a variant of [`ClientError`] if there is en error connecting to the Workload API or
    /// there is a problem processing the response.
    pub fn fetch_x509_svid(&self) -> Result<X509Svid, ClientError> {
        let request = X509SVIDRequest::new();

        let mut response = self
            .client
            .fetch_x509_svid_opt(&request, WorkloadApiClient::call_options()?)?;

        let item = block_on(response.next());
        let x509_svid = WorkloadApiClient::process_x509_svid(item)?;
        Ok(x509_svid)
    }

    /// Fetches the list of all [`X509-Svid`].
    ///
    /// # Errors
    ///
    /// The function returns a variant of [`ClientError`] if there is en error connecting to the Workload API or
    /// there is a problem processing the response.
    pub fn fetch_x509_svids(&self) -> Result<Vec<X509Svid>, ClientError> {
        let request = X509SVIDRequest::new();

        let mut response = self
            .client
            .fetch_x509_svid_opt(&request, WorkloadApiClient::call_options()?)?;

        let item = block_on(response.next());
        let x509_svids = WorkloadApiClient::process_x509_svids(item)?;
        Ok(x509_svids)
    }

    /// Fetches [`JwtBundleSet`] that is a set of [`JwtBundle`] keyed by the trust domain to which they belong.
    ///
    /// # Errors
    ///
    /// The function returns a variant of [`ClientError`] if there is en error connecting to the Workload API or
    /// there is a problem processing the response.
    pub fn fetch_jwt_bundles(&self) -> Result<JwtBundleSet, ClientError> {
        let request = JWTBundlesRequest::new();

        let mut response = self
            .client
            .fetch_jwt_bundles_opt(&request, WorkloadApiClient::call_options()?)?;

        let item = block_on(response.next());
        let jwt_bundle_set = WorkloadApiClient::process_jwt_bundles_response(item)?;
        Ok(jwt_bundle_set)
    }

    /// Fetches [`X509BundleSet`], that is a set of [`X509Bundle`] keyed by the trust domain to which they belong.
    ///
    /// # Errors
    ///
    /// The function returns a variant of [`ClientError`] if there is en error connecting to the Workload API or
    /// there is a problem processing the response.
    pub fn fetch_x509_bundles(&self) -> Result<X509BundleSet, ClientError> {
        let request = X509BundlesRequest::new();

        let mut response = self
            .client
            .fetch_x509_bundles_opt(&request, WorkloadApiClient::call_options()?)?;

        let item = block_on(response.next());
        let x509_bundle_set = WorkloadApiClient::process_x509_bundles_response(item)?;
        Ok(x509_bundle_set)
    }

    /// Fetches the [`X509Context`], which contains all the X.509 materials,
    /// i.e. X509-SVIDs and X.509 bundles.
    ///
    /// # Errors
    ///
    /// The function returns a variant of [`ClientError`] if there is en error connecting to the Workload API or
    /// there is a problem processing the response.
    pub fn fetch_x509_context(&self) -> Result<X509Context, ClientError> {
        let request = X509SVIDRequest::new();

        let mut response = self
            .client
            .fetch_x509_svid_opt(&request, WorkloadApiClient::call_options()?)?;

        let item = block_on(response.next());
        let x509_context = WorkloadApiClient::process_x509_context(item)?;
        Ok(x509_context)
    }

    /// Fetches a [`JwtSvid`] parsing the JWT token in the Workload API response, for the given audience and spiffe_id.
    ///
    /// # Arguments
    ///
    /// * `audience`  - A list of audiences to include in the JWT token. Cannot be empty nor contain only empty strings.
    /// * `spiffe_id` - Optional [`SpiffeId`] for the token 'sub' claim. If not provided, the Workload API returns the
    /// default identity.
    ///
    /// # Errors
    ///
    /// The function returns a variant of [`ClientError`] if there is en error connecting to the Workload API or
    /// there is a problem processing the response.
    ///
    /// IMPORTANT: If there's no registration entries with the requested [`SpiffeId`] mapped to the calling workload,
    /// it will return a [`ClientError::EmptyResponse`].
    pub fn fetch_jwt_svid<T: AsRef<str> + ToString>(
        &self,
        audience: &[T],
        spiffe_id: Option<&SpiffeId>,
    ) -> Result<JwtSvid, ClientError> {
        let response = self.fetch_jwt(audience, spiffe_id)?;
        match response.svids.get(DEFAULT_SVID) {
            Some(r) => Ok(JwtSvid::from_str(&r.svid)?),
            None => Err(ClientError::EmptyResponse),
        }
    }

    /// Fetches a JWT token for the given audience and [`SpiffeId`].
    ///
    /// # Arguments
    ///
    /// * `audience`  - A list of audiences to include in the JWT token. Cannot be empty nor contain only empty strings.
    /// * `spiffe_id` - Optional reference [`SpiffeId`] for the token 'sub' claim. If not provided, the Workload API returns the
    /// default identity,
    ///
    /// # Errors
    ///
    /// The function returns a variant of [`ClientError`] if there is en error connecting to the Workload API or
    /// there is a problem processing the response.
    ///
    /// IMPORTANT: If there's no registration entries with the requested [`SpiffeId`] mapped to the calling workload,
    /// it will return a [`ClientError::EmptyResponse`].
    pub fn fetch_jwt_token<T: AsRef<str> + ToString>(
        &self,
        audience: &[T],
        spiffe_id: Option<&SpiffeId>,
    ) -> Result<String, ClientError> {
        let response = self.fetch_jwt(audience, spiffe_id)?;
        match response.svids.get(DEFAULT_SVID) {
            Some(r) => Ok(r.svid.to_string()),
            None => Err(ClientError::EmptyResponse),
        }
    }

    /// Validates a JWT SVID token against the given audience. Returns the [`JwtSvid`] parsed from
    /// the validated token.
    ///
    /// # Arguments
    ///
    /// * `audience`  - The audience of the validating party. Cannot be empty nor contain an empty string.
    /// * `jwt_token` - The JWT token to validate.
    ///
    /// # Errors
    ///
    /// The function returns a variant of [`ClientError`] if there is en error connecting to the Workload API or
    /// there is a problem processing the response.
    pub fn validate_jwt_token<T: AsRef<str> + ToString>(
        &self,
        audience: T,
        jwt_token: &str,
    ) -> Result<JwtSvid, ClientError> {
        // validate token with Workload API, the returned claims and spiffe_id are ignored as
        // they are parsed from token when the `JwtSvid` object is created, this way we avoid having
        // to validate that the response from the Workload API contains correct claims.
        let _ = self.validate_jwt(audience, jwt_token)?;
        let jwt_svid = JwtSvid::parse_insecure(jwt_token)?;
        Ok(jwt_svid)
    }

    /// Watches for updates to the [`X509Context`], which contains all the X.509 materials,
    /// i.e. X509-SVIDs and X.509 bundles.
    ///
    /// Returns a stream of [`X509Context`] items.
    ///
    /// # Errors
    ///
    /// The function returns a variant of [`ClientError`] if there is an error connecting to the Workload API.
    pub fn watch_x509_context_stream(
        &self,
    ) -> Result<impl Stream<Item = Result<X509Context, ClientError>>, ClientError> {
        let request = X509SVIDRequest::new();

        let response = self
            .client
            .fetch_x509_svid_opt(&request, WorkloadApiClient::call_options()?)?;

        let stream = response.map(|item| match item {
            Ok(resp) => WorkloadApiClient::parse_x509_context_from_grpc_response(resp),
            Err(e) => Err(ClientError::Grpc(e)),
        });

        Ok(stream)
    }
}

// Private methods
impl WorkloadApiClient {
    fn call_options() -> Result<CallOption, ClientError> {
        let mut metadata = grpcio::MetadataBuilder::new();
        metadata.add_str(SPIFFE_HEADER_KEY, SPIFFE_HEADER_VALUE)?;
        let call_options = ::grpcio::CallOption::default().headers(metadata.build());
        Ok(call_options)
    }

    fn fetch_jwt<T: AsRef<str> + ToString>(
        &self,
        audience: &[T],
        spiffe_id: Option<&SpiffeId>,
    ) -> Result<JWTSVIDResponse, ClientError> {
        let mut request = JWTSVIDRequest::new();
        if let Some(s) = spiffe_id {
            request.spiffe_id = s.to_string()
        }
        audience
            .iter()
            .for_each(|s| request.audience.push(s.to_string()));

        self.client
            .fetch_jwtsvid_opt(&request, WorkloadApiClient::call_options()?)
            .map_err(|e| e.into())
    }

    fn process_x509_context(
        item: Option<Result<X509SVIDResponse, grpcio::Error>>,
    ) -> Result<X509Context, ClientError> {
        let x509_context = match item {
            None => return Err(ClientError::EmptyResponse),
            Some(Ok(item)) => WorkloadApiClient::parse_x509_context_from_grpc_response(item)?,
            Some(Err(e)) => return Err(ClientError::Grpc(e)),
        };
        Ok(x509_context)
    }

    fn process_x509_svid(
        item: Option<Result<X509SVIDResponse, grpcio::Error>>,
    ) -> Result<X509Svid, ClientError> {
        let x509_svid = match item {
            None => return Err(ClientError::EmptyResponse),
            Some(Ok(item)) => WorkloadApiClient::parse_x509_svid_from_grpc_response(item)?,
            Some(Err(e)) => return Err(ClientError::Grpc(e)),
        };
        Ok(x509_svid)
    }

    fn process_x509_svids(
        item: Option<Result<X509SVIDResponse, grpcio::Error>>,
    ) -> Result<Vec<X509Svid>, ClientError> {
        let x509_svids = match item {
            None => return Err(ClientError::EmptyResponse),
            Some(Ok(item)) => WorkloadApiClient::parse_x509_svids_from_grpc_response(item)?,
            Some(Err(e)) => return Err(ClientError::Grpc(e)),
        };
        Ok(x509_svids)
    }

    fn process_x509_bundles_response(
        item: Option<Result<X509BundlesResponse, grpcio::Error>>,
    ) -> Result<X509BundleSet, ClientError> {
        let x509_bundle_set = match item {
            None => return Err(ClientError::EmptyResponse),
            Some(Ok(item)) => WorkloadApiClient::parse_x509_bundle_set_from_grpc_response(item)?,
            Some(Err(e)) => return Err(ClientError::Grpc(e)),
        };
        Ok(x509_bundle_set)
    }

    fn process_jwt_bundles_response(
        item: Option<Result<JWTBundlesResponse, grpcio::Error>>,
    ) -> Result<JwtBundleSet, ClientError> {
        let jwt_bundle_set = match item {
            None => return Err(ClientError::EmptyResponse),
            Some(Ok(item)) => WorkloadApiClient::parse_jwt_bundle_set_from_grpc_response(item)?,
            Some(Err(e)) => return Err(ClientError::Grpc(e)),
        };
        Ok(jwt_bundle_set)
    }

    fn parse_x509_context_from_grpc_response(
        response: X509SVIDResponse,
    ) -> Result<X509Context, ClientError> {
        let mut svids = Vec::new();
        let mut bundle_set = X509BundleSet::new();
        for svid in response.svids.into_iter() {
            let x509_svid =
                match X509Svid::parse_from_der(svid.get_x509_svid(), svid.get_x509_svid_key()) {
                    Ok(s) => s,
                    Err(e) => return Err(e.into()),
                };
            let trust_domain = x509_svid.spiffe_id().trust_domain().clone();
            svids.push(x509_svid);
            let bundle = match X509Bundle::parse_from_der(trust_domain, svid.get_bundle()) {
                Ok(b) => b,
                Err(e) => return Err(e.into()),
            };
            bundle_set.add_bundle(bundle);
        }

        Ok(X509Context::new(svids, bundle_set))
    }

    fn parse_x509_svid_from_grpc_response(
        response: X509SVIDResponse,
    ) -> Result<X509Svid, ClientError> {
        let svid = match response.svids.get(DEFAULT_SVID) {
            None => return Err(ClientError::EmptyResponse),
            Some(s) => s,
        };
        let x509_svid =
            match X509Svid::parse_from_der(svid.get_x509_svid(), svid.get_x509_svid_key()) {
                Ok(s) => s,
                Err(e) => return Err(e.into()),
            };
        Ok(x509_svid)
    }

    fn parse_x509_svids_from_grpc_response(
        response: X509SVIDResponse,
    ) -> Result<Vec<X509Svid>, ClientError> {
        let mut x509_svids = Vec::new();
        for svid in response.svids.into_iter() {
            let svid =
                match X509Svid::parse_from_der(svid.get_x509_svid(), svid.get_x509_svid_key()) {
                    Ok(s) => s,
                    Err(e) => return Err(e.into()),
                };
            x509_svids.push(svid);
        }
        Ok(x509_svids)
    }

    fn parse_x509_bundle_set_from_grpc_response(
        response: X509BundlesResponse,
    ) -> Result<X509BundleSet, ClientError> {
        let mut bundle_set = X509BundleSet::new();

        for (td, bundle) in response.bundles.into_iter() {
            let trust_domain = TrustDomain::try_from(td)?;
            let bundle = match X509Bundle::parse_from_der(trust_domain, &bundle) {
                Ok(b) => b,
                Err(e) => return Err(e.into()),
            };
            bundle_set.add_bundle(bundle);
        }
        Ok(bundle_set)
    }

    fn parse_jwt_bundle_set_from_grpc_response(
        response: JWTBundlesResponse,
    ) -> Result<JwtBundleSet, ClientError> {
        let mut bundle_set = JwtBundleSet::new();

        for (td, bundle) in response.bundles.into_iter() {
            let trust_domain = TrustDomain::try_from(td)?;
            let bundle = match JwtBundle::from_jwt_authorities(trust_domain, &bundle) {
                Ok(b) => b,
                Err(e) => return Err(e.into()),
            };
            bundle_set.add_bundle(bundle);
        }
        Ok(bundle_set)
    }

    fn validate_jwt<T: AsRef<str> + ToString>(
        &self,
        audience: T,
        jwt_svid: &str,
    ) -> Result<ValidateJWTSVIDResponse, ClientError> {
        let mut request = ValidateJWTSVIDRequest::new();
        request.set_audience(audience.to_string());
        request.set_svid(jwt_svid.to_string());

        self.client
            .validate_jwtsvid_opt(&request, WorkloadApiClient::call_options()?)
            .map_err(|e| e.into())
    }
}
