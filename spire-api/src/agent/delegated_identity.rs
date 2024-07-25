//! This module provides an API surface to interact with the DelegateIdentity API.
//! The protobuf definition can be found [here](https://github.com/spiffe/spire-api-sdk/blob/main/proto/spire/api/agent/delegatedidentity/v1/delegatedidentity.proto)
//!
//! More information on it's usage can be found in the [SPIFFE docs](https://spiffe.io/docs/latest/deploying/spire_agent/#delegated-identity-api)
//!
//! Most importantly, this API cannot be used over the standard endpoint, it must be used over the admin socket.
//! The admin socket can be configured in the SPIRE agent configuration document.

use crate::proto::spire::api::agent::delegatedidentity::v1::delegated_identity_client::DelegatedIdentityClient as DelegatedIdentityApiClient;
use crate::proto::spire::api::agent::delegatedidentity::v1::{
    FetchJwtsviDsRequest, SubscribeToJwtBundlesRequest, SubscribeToJwtBundlesResponse,
    SubscribeToX509BundlesRequest, SubscribeToX509BundlesResponse, SubscribeToX509sviDsRequest,
    SubscribeToX509sviDsResponse,
};
use crate::proto::spire::api::types::Jwtsvid as ProtoJwtSvid;
use spiffe::endpoint::validate_socket_path;
use spiffe::{JwtBundle, JwtBundleSet, JwtSvid, TrustDomain, X509Bundle, X509BundleSet, X509Svid};
use tokio_stream::{Stream, StreamExt};

use crate::selectors::Selector;
use spiffe::constants::DEFAULT_SVID;
use spiffe::error::GrpcClientError;
use std::convert::{Into, TryFrom};
use std::str::FromStr;
use tokio::net::UnixStream;
use tonic::transport::{Endpoint, Uri};
use tower::service_fn;

/// Name of the environment variable that holds the default socket endpoint path.
pub const ADMIN_SOCKET_ENV: &str = "SPIRE_ADMIN_ENDPOINT_SOCKET";

/// Gets the endpoint socket endpoint path from the environment variable `ADMIN_SOCKET_ENV`,
/// as described in [SPIFFE standard](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_Endpoint.md#4-locating-the-endpoint).
pub fn get_admin_socket_path() -> Option<String> {
    match std::env::var(ADMIN_SOCKET_ENV) {
        Ok(addr) => Some(addr),
        Err(_) => None,
    }
}

/// Impl for DelegatedIdentity API
#[derive(Debug, Clone)]
pub struct DelegatedIdentityClient {
    client: DelegatedIdentityApiClient<tonic::transport::Channel>,
}

/// Represents that a delegate attestation request can have one-of
/// PID (let agent attest PID->selectors) or selectors (delegate has already attested a PID)
#[derive(Debug, Clone)]
pub enum DelegateAttestationRequest {
    /// PID (let agent attest PID->selectors)
    Pid(i32),
    /// selectors (delegate has already attested a PID and generated full set of selectors)
    Selectors(Vec<Selector>),
}

/// Constructors
impl DelegatedIdentityClient {
    const UNIX_PREFIX: &'static str = "unix:";
    const TONIC_DEFAULT_URI: &'static str = "http://[::]:50051";

    /// Creates a new instance of `DelegatedIdentityClient` by connecting to the specified socket path.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to the UNIX domain socket, which can optionally start with "unix:".
    ///
    /// # Returns
    ///
    /// * `Result<Self, ClientError>` - Returns an instance of `DelegatedIdentityClient` if successful, otherwise returns an error.
    ///
    /// # Errors
    ///
    /// This function will return an error if the provided socket path is invalid or if there are issues connecting.
    pub async fn new_from_path(path: &str) -> Result<Self, GrpcClientError> {
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

        Ok(DelegatedIdentityClient {
            client: DelegatedIdentityApiClient::new(channel),
        })
    }

    /// Creates a new `DelegatedIdentityClient` using the default socket endpoint address.
    ///
    /// Requires that the environment variable `SPIFFE_ENDPOINT_SOCKET` be set with
    /// the path to the Workload API endpoint socket.
    ///
    /// # Errors
    ///
    /// The function returns a variant of [`GrpcClientError`] if environment variable is not set or if
    /// the provided socket path is not valid.
    pub async fn default() -> Result<Self, GrpcClientError> {
        let socket_path = match get_admin_socket_path() {
            None => return Err(GrpcClientError::MissingEndpointSocketPath),
            Some(s) => s,
        };
        Self::new_from_path(socket_path.as_str()).await
    }

    /// Constructs a new `DelegatedIdentityClient` using the provided Tonic transport channel.
    ///
    /// # Arguments
    ///
    /// * `conn`: A `tonic::transport::Channel` used for gRPC communication.
    ///
    /// # Returns
    ///
    /// A `Result` containing a `DelegatedIdentityClient` if successful, or a `ClientError` if an error occurs.
    pub fn new(conn: tonic::transport::Channel) -> Result<Self, GrpcClientError> {
        Ok(DelegatedIdentityClient {
            client: DelegatedIdentityApiClient::new(conn),
        })
    }
}

impl DelegatedIdentityClient {
    /// Fetches a single X509 SPIFFE Verifiable Identity Document (SVID).
    ///
    /// This method connects to the SPIFFE Workload API and returns the first X509 SVID in the response.
    ///
    /// # Arguments
    ///
    /// * `selectors` - A list of selectors to filter the stream of [`X509Svid`] updates.
    ///
    /// # Returns
    ///
    /// On success, it returns a valid [`X509Svid`] which represents the parsed SVID.
    /// If the fetch operation or the parsing fails, it returns a [`GrpcClientError`].
    ///
    /// # Errors
    ///
    /// Returns [`GrpcClientError`] if the gRPC call fails or if the SVID could not be parsed from the gRPC response.
    pub async fn fetch_x509_svid(
        &mut self,
        attest_type: DelegateAttestationRequest,
    ) -> Result<X509Svid, GrpcClientError> {
        let request = match attest_type {
            DelegateAttestationRequest::Selectors(selectors) => SubscribeToX509sviDsRequest {
                selectors: selectors.into_iter().map(|s| s.into()).collect(),
                pid: 0,
            },
            DelegateAttestationRequest::Pid(pid) => SubscribeToX509sviDsRequest {
                selectors: Vec::default(),
                pid,
            },
        };

        self.client
            .subscribe_to_x509svi_ds(request)
            .await?
            .into_inner()
            .message()
            .await?
            .ok_or(GrpcClientError::EmptyResponse)
            .and_then(DelegatedIdentityClient::parse_x509_svid_from_grpc_response)
    }

    /// Watches the stream of [`X509Svid`] updates.
    ///
    /// This function establishes a stream with the Workload API to continuously receive updates for the [`X509Svid`].
    /// The returned stream can be used to asynchronously yield new `X509Svid` updates as they become available.
    ///
    /// # Arguments
    ///
    /// * `selectors` - A list of selectors to filter the stream of [`X509Svid`] updates.
    ///
    /// # Returns
    ///
    /// Returns a stream of `Result<X509Svid, ClientError>`. Each item represents an updated [`X509Svid`] or an error if
    /// there was a problem processing an update from the stream.
    ///
    /// # Errors
    ///
    /// The function can return an error variant of [`GrpcClientError`] in the following scenarios:
    ///
    /// * There's an issue connecting to the Workload API.
    /// * An error occurs while setting up the stream.
    ///
    /// Individual stream items might also be errors if there's an issue processing the response for a specific update.
    pub async fn stream_x509_svids(
        &mut self,
        attest_type: DelegateAttestationRequest,
    ) -> Result<impl Stream<Item = Result<X509Svid, GrpcClientError>>, GrpcClientError> {
        let request = match attest_type {
            DelegateAttestationRequest::Selectors(selectors) => SubscribeToX509sviDsRequest {
                selectors: selectors.into_iter().map(|s| s.into()).collect(),
                pid: 0,
            },
            DelegateAttestationRequest::Pid(pid) => SubscribeToX509sviDsRequest {
                selectors: Vec::default(),
                pid,
            },
        };

        let response: tonic::Response<tonic::Streaming<SubscribeToX509sviDsResponse>> =
            self.client.subscribe_to_x509svi_ds(request).await?;

        let stream = response.into_inner().map(|message| {
            message
                .map_err(GrpcClientError::from)
                .and_then(DelegatedIdentityClient::parse_x509_svid_from_grpc_response)
        });

        Ok(stream)
    }

    /// Fetches [`X509BundleSet`], that is a set of [`X509Bundle`] keyed by the trust domain to which they belong.
    ///
    /// # Errors
    ///
    /// The function returns a variant of [`GrpcClientError`] if there is en error connecting to the Workload API or
    /// there is a problem processing the response.
    pub async fn fetch_x509_bundles(&mut self) -> Result<X509BundleSet, GrpcClientError> {
        let request = SubscribeToX509BundlesRequest::default();

        let response: tonic::Response<tonic::Streaming<SubscribeToX509BundlesResponse>> =
            self.client.subscribe_to_x509_bundles(request).await?;
        let initial = response.into_inner().message().await?;
        DelegatedIdentityClient::parse_x509_bundle_set_from_grpc_response(
            initial.unwrap_or_default(),
        )
    }

    /// Watches the stream of [`X509Bundle`] updates.
    ///
    /// This function establishes a stream with the Workload API to continuously receive updates for the [`X509Bundle`].
    /// The returned stream can be used to asynchronously yield new `X509Bundle` updates as they become available.
    ///
    /// # Returns
    ///
    /// Returns a stream of `Result<X509Bundle, ClientError>`. Each item represents an updated [`X509Bundle`] or an error if
    /// there was a problem processing an update from the stream.
    ///
    /// # Errors
    ///
    /// The function can return an error variant of [`GrpcClientError`] in the following scenarios:
    ///
    /// * There's an issue connecting to the Admin API.
    /// * An error occurs while setting up the stream.
    ///
    /// Individual stream items might also be errors if there's an issue processing the response for a specific update.
    pub async fn stream_x509_bundles(
        &mut self,
    ) -> Result<impl Stream<Item = Result<X509BundleSet, GrpcClientError>>, GrpcClientError> {
        let request = SubscribeToX509BundlesRequest::default();

        let response: tonic::Response<tonic::Streaming<SubscribeToX509BundlesResponse>> =
            self.client.subscribe_to_x509_bundles(request).await?;

        let stream = response.into_inner().map(|message| {
            message
                .map_err(GrpcClientError::from)
                .and_then(DelegatedIdentityClient::parse_x509_bundle_set_from_grpc_response)
        });

        Ok(stream)
    }

    /// Fetches a list of [`JwtSvid`] parsing the JWT token in the Workload API response, for the given audience and selectors.
    ///
    /// # Arguments
    ///
    /// * `audience`  - A list of audiences to include in the JWT token. Cannot be empty nor contain only empty strings.
    /// * `selectors` - A list of selectors to filter the list of [`JwtSvid`].
    ///
    /// # Errors
    ///
    /// The function returns a variant of [`GrpcClientError`] if there is en error connecting to the Workload API or
    /// there is a problem processing the response.
    pub async fn fetch_jwt_svids<T: AsRef<str> + ToString>(
        &mut self,
        audience: &[T],
        attest_type: DelegateAttestationRequest,
    ) -> Result<Vec<JwtSvid>, GrpcClientError> {
        let request = match attest_type {
            DelegateAttestationRequest::Selectors(selectors) => FetchJwtsviDsRequest {
                audience: audience.iter().map(|s| s.to_string()).collect(),
                selectors: selectors.into_iter().map(|s| s.into()).collect(),
                pid: 0,
            },
            DelegateAttestationRequest::Pid(pid) => FetchJwtsviDsRequest {
                audience: audience.iter().map(|s| s.to_string()).collect(),
                selectors: Vec::default(),
                pid,
            },
        };

        DelegatedIdentityClient::parse_jwt_svid_from_grpc_response(
            self.client
                .fetch_jwtsvi_ds(request)
                .await?
                .into_inner()
                .svids,
        )
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
    /// The function can return an error variant of [`GrpcClientError`] in the following scenarios:
    ///
    /// * There's an issue connecting to the Workload API.
    /// * An error occurs while setting up the stream.
    ///
    /// Individual stream items might also be errors if there's an issue processing the response for a specific update.
    pub async fn stream_jwt_bundles(
        &mut self,
    ) -> Result<impl Stream<Item = Result<JwtBundleSet, GrpcClientError>>, GrpcClientError> {
        let request = SubscribeToJwtBundlesRequest::default();
        let response = self.client.subscribe_to_jwt_bundles(request).await?;
        Ok(response.into_inner().map(|message| {
            message
                .map_err(GrpcClientError::from)
                .and_then(DelegatedIdentityClient::parse_jwt_bundle_set_from_grpc_response)
        }))
    }

    /// Fetches [`JwtBundleSet`] that is a set of [`JwtBundle`] keyed by the trust domain to which they belong.
    ///
    /// # Errors
    ///
    /// The function returns a variant of [`GrpcClientError`] if there is en error connecting to the Workload API or
    /// there is a problem processing the response.
    pub async fn fetch_jwt_bundles(&mut self) -> Result<JwtBundleSet, GrpcClientError> {
        let request = SubscribeToJwtBundlesRequest::default();
        let response = self.client.subscribe_to_jwt_bundles(request).await?;
        let initial = response.into_inner().message().await?;
        DelegatedIdentityClient::parse_jwt_bundle_set_from_grpc_response(
            initial.ok_or(GrpcClientError::EmptyResponse)?,
        )
    }
}

impl DelegatedIdentityClient {
    fn parse_x509_svid_from_grpc_response(
        response: SubscribeToX509sviDsResponse,
    ) -> Result<X509Svid, GrpcClientError> {
        let svid = response
            .x509_svids
            .get(DEFAULT_SVID)
            .ok_or(GrpcClientError::EmptyResponse)?;

        let x509_svid = svid
            .x509_svid
            .as_ref()
            .ok_or(GrpcClientError::EmptyResponse)?;

        let total_length = x509_svid.cert_chain.iter().map(|c| c.len()).sum();
        let mut cert_chain_bytes = Vec::with_capacity(total_length);

        for c in &x509_svid.cert_chain {
            cert_chain_bytes.extend_from_slice(c);
        }

        X509Svid::parse_from_der(&cert_chain_bytes, svid.x509_svid_key.as_ref())
            .map_err(|e| e.into())
    }

    fn parse_jwt_svid_from_grpc_response(
        svids: Vec<ProtoJwtSvid>,
    ) -> Result<Vec<JwtSvid>, GrpcClientError> {
        let result: Result<Vec<JwtSvid>, GrpcClientError> = svids
            .iter()
            .map(|r| JwtSvid::from_str(&r.token).map_err(GrpcClientError::InvalidJwtSvid))
            .collect();
        result
    }

    fn parse_jwt_bundle_set_from_grpc_response(
        response: SubscribeToJwtBundlesResponse,
    ) -> Result<JwtBundleSet, GrpcClientError> {
        let mut bundle_set = JwtBundleSet::new();

        for (td, bundle_data) in response.bundles.into_iter() {
            let trust_domain = TrustDomain::try_from(td)?;
            let bundle = JwtBundle::from_jwt_authorities(trust_domain, &bundle_data)
                .map_err(GrpcClientError::from)?;

            bundle_set.add_bundle(bundle);
        }

        Ok(bundle_set)
    }

    fn parse_x509_bundle_set_from_grpc_response(
        response: SubscribeToX509BundlesResponse,
    ) -> Result<X509BundleSet, GrpcClientError> {
        let mut bundle_set = X509BundleSet::new();

        for (td, bundle) in response.ca_certificates.into_iter() {
            let trust_domain = TrustDomain::try_from(td)?;

            bundle_set.add_bundle(
                X509Bundle::parse_from_der(trust_domain, &bundle)
                    .map_err(GrpcClientError::InvalidX509Bundle)?,
            );
        }
        Ok(bundle_set)
    }
}
