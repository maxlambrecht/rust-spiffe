//! A Workload API client implementation to fetch X.509 and JWT materials.
//! # Examples
//!
//! ```no_run
//! use tokio_stream::StreamExt;
//! use std::error::Error;
//! use spiffe::workload_api::client::WorkloadApiClient;
//! use spiffe::bundle::x509::X509BundleSet;
//! use spiffe::svid::x509::X509Svid;
//! use spiffe::workload_api::x509_context::X509Context;
//!
//! # async fn example() -> Result<(), Box< dyn Error>> {
//!
//! let mut client = WorkloadApiClient::new_from_path("unix:/tmp/spire-agent/public/api.sock").await?;
//!
//! let target_audience = &["service1", "service2"];
//! // fetch a jwt token for the default identity with the target audience
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
//! // watch for updates on the X.509 context
//! let mut x509_context_stream = client.watch_x509_context_stream().await?;
//! while let Some(x509_context_update) = x509_context_stream.next().await {
//!     match x509_context_update {
//!         Ok(context) => {
//!             // handle the updated X509Context
//!         }
//!         Err(e) => {
//!             // handle the error
//!         }
//!     }
//! }
//!
//! # Ok(())
//! # }
//! ```

use std::str::FromStr;

use thiserror::Error;

use crate::bundle::jwt::{JwtBundle, JwtBundleError, JwtBundleSet};
use crate::bundle::x509::{X509Bundle, X509BundleError, X509BundleSet};
use crate::spiffe_id::{SpiffeId, SpiffeIdError, TrustDomain};
use crate::svid::jwt::{JwtSvid, JwtSvidError};
use crate::svid::x509::{X509Svid, X509SvidError};
use crate::workload_api::address::{
    get_default_socket_path, validate_socket_path, SocketPathError,
};
use crate::workload_api::x509_context::X509Context;
use std::convert::TryFrom;

use tokio::net::UnixStream;
use tokio_stream::{Stream, StreamExt};

use crate::proto::workload::{
    spiffe_workload_api_client::SpiffeWorkloadApiClient, JwtBundlesRequest, JwtBundlesResponse,
    JwtsvidRequest, JwtsvidResponse, ValidateJwtsvidRequest, ValidateJwtsvidResponse,
    X509BundlesRequest, X509BundlesResponse, X509svidRequest, X509svidResponse,
};
use tonic::transport::{Endpoint, Uri};
use tower::service_fn;

/// The default SVID is the first in the list of SVIDs returned by the Workload API.
pub const DEFAULT_SVID: usize = 0;

const SPIFFE_HEADER_KEY: &str = "workload.spiffe.io";
const SPIFFE_HEADER_VALUE: &str = "true";

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

    /// Error returned by the GRPC library, when there is an error response from the Workload API.
    #[error("error response from the Workload API")]
    Grpc(#[from] tonic::Status),

    /// Error returned by the GRPC library when there is an error creating a transport channel to the Workload API.
    #[error("error creating transport")]
    Transport(#[from] tonic::transport::Error),
}

/// This type represents a client to interact with the Workload API.
///
/// Supports one-shot calls and streaming updates for X.509 and JWT SVIDs and bundles.
/// The client can be used to fetch the current SVIDs and bundles, as well as to
/// subscribe for updates whenever the SVIDs or bundles change.
#[allow(missing_debug_implementations)]
#[derive(Clone)]
pub struct WorkloadApiClient {
    client: SpiffeWorkloadApiClient<
        tonic::service::interceptor::InterceptedService<tonic::transport::Channel, MetadataAdder>,
    >,
}

#[derive(Clone)]
struct MetadataAdder;

impl tonic::service::Interceptor for MetadataAdder {
    fn call(
        &mut self,
        mut request: tonic::Request<()>,
    ) -> Result<tonic::Request<()>, tonic::Status> {
        let parsed_header = SPIFFE_HEADER_VALUE
            .parse()
            .map_err(|e| tonic::Status::internal(format!("Failed to parse header: {}", e)))?;
        request
            .metadata_mut()
            .insert(SPIFFE_HEADER_KEY, parsed_header);
        Ok(request)
    }
}

impl WorkloadApiClient {
    const UNIX_PREFIX: &'static str = "unix:";
    const TONIC_DEFAULT_URI: &'static str = "http://[::]:50051";

    /// Creates a new instance of `WorkloadApiClient` by connecting to the specified socket path.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to the UNIX domain socket, which can optionally start with "unix:".
    ///
    /// # Returns
    ///
    /// * `Result<Self, ClientError>` - Returns an instance of `WorkloadApiClient` if successful, otherwise returns an error.
    ///
    /// # Errors
    ///
    /// This function will return an error if the provided socket path is invalid or if there are issues connecting.
    pub async fn new_from_path(path: &str) -> Result<Self, ClientError> {
        validate_socket_path(path)?;

        // Strip the 'unix:' prefix for tonic compatibility.
        let stripped_path = path
            .strip_prefix(Self::UNIX_PREFIX)
            .unwrap_or(path)
            .to_string();

        let channel = Endpoint::try_from(Self::TONIC_DEFAULT_URI)?
            .connect_with_connector(service_fn(move |_: Uri| {
                // Connect to the UDS socket using the modified path.
                UnixStream::connect(stripped_path.clone())
            }))
            .await?;

        Ok(WorkloadApiClient {
            client: SpiffeWorkloadApiClient::with_interceptor(channel, MetadataAdder {}),
        })
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
    pub async fn default() -> Result<Self, ClientError> {
        let socket_path =
            get_default_socket_path().ok_or(ClientError::MissingEndpointSocketPath)?;
        Self::new_from_path(socket_path.as_str()).await
    }

    /// Constructs a new `WorkloadApiClient` using the provided Tonic transport channel.
    ///
    /// # Arguments
    ///
    /// * `conn`: A `tonic::transport::Channel` used for gRPC communication.
    ///
    /// # Returns
    ///
    /// A `Result` containing a `WorkloadApiClient` if successful, or a `ClientError` if an error occurs.
    pub fn new(conn: tonic::transport::Channel) -> Result<Self, ClientError> {
        Ok(WorkloadApiClient {
            client: SpiffeWorkloadApiClient::with_interceptor(conn, MetadataAdder {}),
        })
    }

    /// Fetches a single X509 SPIFFE Verifiable Identity Document (SVID).
    ///
    /// This method connects to the SPIFFE Workload API and returns the first X509 SVID in the response.
    ///
    /// # Returns
    ///
    /// On success, it returns a valid [`X509Svid`] which represents the parsed SVID.
    /// If the fetch operation or the parsing fails, it returns a [`ClientError`].
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] if the gRPC call fails or if the SVID could not be parsed from the gRPC response.
    pub async fn fetch_x509_svid(&mut self) -> Result<X509Svid, ClientError> {
        let request = X509svidRequest::default();

        let grpc_stream_response: tonic::Response<tonic::Streaming<X509svidResponse>> =
            self.client.fetch_x509svid(request).await?;

        let response = grpc_stream_response
            .into_inner()
            .message()
            .await?
            .ok_or(ClientError::EmptyResponse)?;
        WorkloadApiClient::parse_x509_svid_from_grpc_response(response)
    }

    /// Fetches all X509 SPIFFE Verifiable Identity Documents (SVIDs) available to the workload.
    ///
    /// This method sends a request to the SPIFFE Workload API, retrieving a stream of X509 SVID responses.
    /// All SVIDs are then parsed and returned as a list.
    ///
    /// # Returns
    ///
    /// On success, it returns a `Vec` containing valid [`X509Svid`] instances, each representing a parsed SVID.
    /// If the fetch operation or any parsing fails, it returns a [`ClientError`].
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] if the gRPC call fails, if the SVIDs could not be parsed from the gRPC response,
    /// or if the stream unexpectedly terminates.
    pub async fn fetch_all_x509_svids(&mut self) -> Result<Vec<X509Svid>, ClientError> {
        let request = X509svidRequest::default();

        let grpc_stream_response: tonic::Response<tonic::Streaming<X509svidResponse>> =
            self.client.fetch_x509svid(request).await?;

        let response = grpc_stream_response
            .into_inner()
            .message()
            .await?
            .ok_or(ClientError::EmptyResponse)?;
        WorkloadApiClient::parse_x509_svids_from_grpc_response(response)
    }

    /// Fetches [`X509BundleSet`], that is a set of [`X509Bundle`] keyed by the trust domain to which they belong.
    ///
    /// # Errors
    ///
    /// The function returns a variant of [`ClientError`] if there is en error connecting to the Workload API or
    /// there is a problem processing the response.
    pub async fn fetch_x509_bundles(&mut self) -> Result<X509BundleSet, ClientError> {
        let request = X509BundlesRequest::default();

        let grpc_stream_response: tonic::Response<tonic::Streaming<X509BundlesResponse>> =
            self.client.fetch_x509_bundles(request).await?;

        let response = grpc_stream_response
            .into_inner()
            .message()
            .await?
            .ok_or(ClientError::EmptyResponse)?;
        WorkloadApiClient::parse_x509_bundle_set_from_grpc_response(response)
    }

    /// Fetches [`JwtBundleSet`] that is a set of [`JwtBundle`] keyed by the trust domain to which they belong.
    ///
    /// # Errors
    ///
    /// The function returns a variant of [`ClientError`] if there is en error connecting to the Workload API or
    /// there is a problem processing the response.
    pub async fn fetch_jwt_bundles(&mut self) -> Result<JwtBundleSet, ClientError> {
        let request = JwtBundlesRequest::default();

        let grpc_stream_response: tonic::Response<tonic::Streaming<JwtBundlesResponse>> =
            self.client.fetch_jwt_bundles(request).await?;

        let response = grpc_stream_response
            .into_inner()
            .message()
            .await?
            .ok_or(ClientError::EmptyResponse)?;
        WorkloadApiClient::parse_jwt_bundle_set_from_grpc_response(response)
    }

    /// Fetches the [`X509Context`], which contains all the X.509 materials,
    /// i.e. X509-SVIDs and X.509 bundles.
    ///
    /// # Errors
    ///
    /// The function returns a variant of [`ClientError`] if there is en error connecting to the Workload API or
    /// there is a problem processing the response.
    pub async fn fetch_x509_context(&mut self) -> Result<X509Context, ClientError> {
        let request = X509svidRequest::default();

        let grpc_stream_response: tonic::Response<tonic::Streaming<X509svidResponse>> =
            self.client.fetch_x509svid(request).await?;

        let response = grpc_stream_response
            .into_inner()
            .message()
            .await?
            .ok_or(ClientError::EmptyResponse)?;
        WorkloadApiClient::parse_x509_context_from_grpc_response(response)
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
    pub async fn fetch_jwt_svid<T: AsRef<str> + ToString>(
        &mut self,
        audience: &[T],
        spiffe_id: Option<&SpiffeId>,
    ) -> Result<JwtSvid, ClientError> {
        let response = self.fetch_jwt(audience, spiffe_id).await?;
        response
            .svids
            .get(DEFAULT_SVID)
            .ok_or(ClientError::EmptyResponse)
            .and_then(|r| {
                JwtSvid::from_str(&r.svid).map_err(|err| ClientError::InvalidJwtSvid(err))
            })
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
    pub async fn fetch_jwt_token<T: AsRef<str> + ToString>(
        &mut self,
        audience: &[T],
        spiffe_id: Option<&SpiffeId>,
    ) -> Result<String, ClientError> {
        let response = self.fetch_jwt(audience, spiffe_id).await?;
        response
            .svids
            .get(DEFAULT_SVID)
            .map(|r| r.svid.to_string())
            .ok_or(ClientError::EmptyResponse)
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
    pub async fn validate_jwt_token<T: AsRef<str> + ToString>(
        &mut self,
        audience: T,
        jwt_token: &str,
    ) -> Result<JwtSvid, ClientError> {
        // validate token with Workload API, the returned claims and spiffe_id are ignored as
        // they are parsed from token when the `JwtSvid` object is created, this way we avoid having
        // to validate that the response from the Workload API contains correct claims.
        let _ = self.validate_jwt(audience, jwt_token).await?;
        let jwt_svid = JwtSvid::parse_insecure(jwt_token)?;
        Ok(jwt_svid)
    }

    /// Watches the stream of [`X509Context`] updates.
    ///
    /// This function establishes a stream with the Workload API to continuously receive updates for the [`X509Context`].
    /// The returned stream can be used to asynchronously yield new `X509Context` updates as they become available.
    ///
    /// # Returns
    ///
    /// Returns a stream of `Result<X509Context, ClientError>`. Each item represents an updated [`X509Context`] or an error if
    /// there was a problem processing an update from the stream.
    ///
    /// # Errors
    ///
    /// The function can return an error variant of [`ClientError`] in the following scenarios:
    ///
    /// * There's an issue connecting to the Workload API.
    /// * An error occurs while setting up the stream.
    ///
    /// Individual stream items might also be errors if there's an issue processing the response for a specific update.
    pub async fn watch_x509_context_stream(
        &mut self,
    ) -> Result<impl Stream<Item = Result<X509Context, ClientError>>, ClientError> {
        let request = X509svidRequest::default();
        let response = self.client.fetch_x509svid(request).await?;
        let stream = response.into_inner().map(|message| {
            message
                .map_err(ClientError::from)
                .and_then(WorkloadApiClient::parse_x509_context_from_grpc_response)
        });
        Ok(stream)
    }

    /// Watches the stream of [`X509Svid`] updates.
    ///
    /// This function establishes a stream with the Workload API to continuously receive updates for the [`X509Svid`].
    /// The returned stream can be used to asynchronously yield new `X509Svid` updates as they become available.
    ///
    /// # Returns
    ///
    /// Returns a stream of `Result<X509Svid, ClientError>`. Each item represents an updated [`X509Svid`] or an error if
    /// there was a problem processing an update from the stream.
    ///
    /// # Errors
    ///
    /// The function can return an error variant of [`ClientError`] in the following scenarios:
    ///
    /// * There's an issue connecting to the Workload API.
    /// * An error occurs while setting up the stream.
    ///
    /// Individual stream items might also be errors if there's an issue processing the response for a specific update.
    pub async fn watch_x509_svid_stream(
        &mut self,
    ) -> Result<impl Stream<Item = Result<X509Svid, ClientError>>, ClientError> {
        let request = X509svidRequest::default();
        let response = self.client.fetch_x509svid(request).await?;
        let stream = response.into_inner().map(|message| {
            message
                .map_err(ClientError::from)
                .and_then(WorkloadApiClient::parse_x509_svid_from_grpc_response)
        });
        Ok(stream)
    }

    /// Watches the stream of [`X509BundleSet`] updates.
    ///
    /// This function establishes a stream with the Workload API to continuously receive updates for the [`X509BundleSet`].
    /// The returned stream can be used to asynchronously yield new `X509BundleSet` updates as they become available.
    ///
    /// # Returns
    ///
    /// Returns a stream of `Result<X509BundleSet, ClientError>`. Each item represents an updated [`X509BundleSet`] or an error if
    /// there was a problem processing an update from the stream.
    ///
    /// # Errors
    ///
    /// The function can return an error variant of [`ClientError`] in the following scenarios:
    ///
    /// * There's an issue connecting to the Workload API.
    /// * An error occurs while setting up the stream.
    ///
    /// Individual stream items might also be errors if there's an issue processing the response for a specific update.
    pub async fn watch_x509_bundles_stream(
        &mut self,
    ) -> Result<impl Stream<Item = Result<X509BundleSet, ClientError>>, ClientError> {
        let request = X509BundlesRequest::default();
        let response = self.client.fetch_x509_bundles(request).await?;
        let stream = response.into_inner().map(|message| {
            message
                .map_err(ClientError::from)
                .and_then(WorkloadApiClient::parse_x509_bundle_set_from_grpc_response)
        });
        Ok(stream)
    }

    /// Watches the stream of [`JwtBundleSet`] updates.
    ///
    /// This function establishes a stream with the Workload API to continuously receive updates for the [`JwtBundleSet`].
    /// The returned stream can be used to asynchronously yield new `JwtBundleSet` updates as they become available.
    ///
    /// # Returns
    ///
    /// Returns a stream of `Result<JwtBundleSet, ClientError>`. Each item represents an updated [`JwtBundleSet`] or an error if
    /// there was a problem processing an update from the stream.
    ///
    /// # Errors
    ///
    /// The function can return an error variant of [`ClientError`] in the following scenarios:
    ///
    /// * There's an issue connecting to the Workload API.
    /// * An error occurs while setting up the stream.
    ///
    /// Individual stream items might also be errors if there's an issue processing the response for a specific update.
    pub async fn watch_jwt_bundles_stream(
        &mut self,
    ) -> Result<impl Stream<Item = Result<JwtBundleSet, ClientError>>, ClientError> {
        let request = JwtBundlesRequest::default();
        let response = self.client.fetch_jwt_bundles(request).await?;
        let stream = response.into_inner().map(|message| {
            message
                .map_err(ClientError::from)
                .and_then(WorkloadApiClient::parse_jwt_bundle_set_from_grpc_response)
        });
        Ok(stream)
    }
}

/// private
impl WorkloadApiClient {
    async fn fetch_jwt<T: AsRef<str> + ToString>(
        &mut self,
        audience: &[T],
        spiffe_id: Option<&SpiffeId>,
    ) -> Result<JwtsvidResponse, ClientError> {
        let request = JwtsvidRequest {
            spiffe_id: spiffe_id.map(ToString::to_string).unwrap_or_default(),
            audience: audience.iter().map(|s| s.to_string()).collect(),
        };

        Ok(self.client.fetch_jwtsvid(request).await?.into_inner())
    }

    async fn validate_jwt<T: AsRef<str>>(
        &mut self,
        audience: T,
        jwt_svid: &str,
    ) -> Result<ValidateJwtsvidResponse, ClientError> {
        let request = ValidateJwtsvidRequest {
            audience: audience.as_ref().into(),
            svid: jwt_svid.into(),
        };

        Ok(self.client.validate_jwtsvid(request).await?.into_inner())
    }

    fn parse_x509_svid_from_grpc_response(
        response: X509svidResponse,
    ) -> Result<X509Svid, ClientError> {
        let svid = response
            .svids
            .get(DEFAULT_SVID)
            .ok_or(ClientError::EmptyResponse)?;

        X509Svid::parse_from_der(svid.x509_svid.as_ref(), svid.x509_svid_key.as_ref())
            .map_err(ClientError::from)
    }

    fn parse_x509_svids_from_grpc_response(
        response: X509svidResponse,
    ) -> Result<Vec<X509Svid>, ClientError> {
        let mut svids_vec = Vec::new();

        for svid in response.svids.iter() {
            let parsed_svid =
                X509Svid::parse_from_der(svid.x509_svid.as_ref(), svid.x509_svid_key.as_ref())
                    .map_err(ClientError::from)?;

            svids_vec.push(parsed_svid);
        }

        Ok(svids_vec)
    }

    fn parse_x509_bundle_set_from_grpc_response(
        response: X509BundlesResponse,
    ) -> Result<X509BundleSet, ClientError> {
        let bundles: Result<Vec<_>, _> = response
            .bundles
            .into_iter()
            .map(|(td, bundle_data)| {
                let trust_domain = TrustDomain::try_from(td)?;
                X509Bundle::parse_from_der(trust_domain, &bundle_data).map_err(ClientError::from)
            })
            .collect();

        let mut bundle_set = X509BundleSet::new();
        for bundle in bundles? {
            bundle_set.add_bundle(bundle);
        }

        Ok(bundle_set)
    }

    fn parse_jwt_bundle_set_from_grpc_response(
        response: JwtBundlesResponse,
    ) -> Result<JwtBundleSet, ClientError> {
        let mut bundle_set = JwtBundleSet::new();

        for (td, bundle_data) in response.bundles.into_iter() {
            let trust_domain = TrustDomain::try_from(td)?;
            let bundle = JwtBundle::from_jwt_authorities(trust_domain, &bundle_data)
                .map_err(ClientError::from)?;

            bundle_set.add_bundle(bundle);
        }

        Ok(bundle_set)
    }

    fn parse_x509_context_from_grpc_response(
        response: X509svidResponse,
    ) -> Result<X509Context, ClientError> {
        let mut svids = Vec::new();
        let mut bundle_set = X509BundleSet::new();

        for svid in response.svids.into_iter() {
            let x509_svid =
                X509Svid::parse_from_der(svid.x509_svid.as_ref(), svid.x509_svid_key.as_ref())
                    .map_err(ClientError::from)?;

            let trust_domain = x509_svid.spiffe_id().trust_domain().clone();
            svids.push(x509_svid);

            let bundle = X509Bundle::parse_from_der(trust_domain, svid.bundle.as_ref())
                .map_err(ClientError::from)?;
            bundle_set.add_bundle(bundle);
        }

        Ok(X509Context::new(svids, bundle_set))
    }
}
