//! Delegate Identity (SPIRE Agent Admin API).
//!
//! Protobuf:
//! - `https://github.com/spiffe/spire-api-sdk/blob/main/proto/spire/api/agent/delegatedidentity/v1/delegatedidentity.proto`
//!
//! Docs:
//! - `https://spiffe.io/docs/latest/deploying/spire_agent/#delegated-identity-api`
//!
//! Notes:
//! - This API must be used over the SPIRE Agent **admin** socket, not the Workload API socket.

use crate::pb::spire::api::agent::delegatedidentity::v1::delegated_identity_client::DelegatedIdentityClient as DelegatedIdentityApiClient;
use crate::pb::spire::api::agent::delegatedidentity::v1::{
    FetchJwtsviDsRequest, SubscribeToJwtBundlesRequest, SubscribeToJwtBundlesResponse,
    SubscribeToX509BundlesRequest, SubscribeToX509BundlesResponse, SubscribeToX509sviDsRequest,
    SubscribeToX509sviDsResponse,
};
use crate::pb::spire::api::types::Jwtsvid as ProtoJwtSvid;

use crate::selectors::Selector;

use spiffe::constants::DEFAULT_SVID;
use spiffe::transport::{Endpoint, TransportError};
use spiffe::{
    JwtBundle, JwtBundleError, JwtBundleSet, JwtSvid, JwtSvidError, SpiffeIdError, TrustDomain,
    X509Bundle, X509BundleError, X509BundleSet, X509Svid, X509SvidError,
};

use std::str::FromStr as _;

use futures::{Stream, StreamExt as _};

/// Name of the environment variable that holds the default socket endpoint path.
pub const ADMIN_SOCKET_ENV: &str = "SPIRE_ADMIN_ENDPOINT_SOCKET";

/// Errors produced by the Delegated Identity API client.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DelegatedIdentityError {
    /// The environment variable for the admin endpoint socket is not set.
    #[error("missing admin endpoint socket path ({ADMIN_SOCKET_ENV})")]
    MissingEndpointSocket,

    /// The environment variable for the admin endpoint socket is not a valid UTF-8 string.
    #[error("admin endpoint socket path is not a valid UTF-8 string: {}", .0.display())]
    NotUnicodeEndpointSocket(std::ffi::OsString),

    /// Failed to parse the endpoint URI.
    #[error("invalid endpoint: {0}")]
    Endpoint(#[from] spiffe::transport::EndpointError),

    /// Transport error while connecting to the API.
    #[error(transparent)]
    Transport(#[from] TransportError),

    /// The API returned an empty response.
    #[error("empty response")]
    EmptyResponse,

    /// Failed to parse a JWT SVID.
    #[error("JWT SVID error: {0}")]
    JwtSvid(#[from] JwtSvidError),

    /// Failed to parse an X.509 bundle.
    #[error("X.509 bundle error: {0}")]
    X509Bundle(#[from] X509BundleError),

    /// Failed to parse an X.509 SVID.
    #[error("X.509 SVID error: {0}")]
    X509Svid(#[from] X509SvidError),

    /// Failed to parse a JWT bundle.
    #[error("JWT bundle error: {0}")]
    JwtBundle(#[from] JwtBundleError),

    /// Failed to parse a SPIFFE identifier.
    #[error("SPIFFE ID error: {0}")]
    SpiffeId(#[from] SpiffeIdError),
}

/// Load the admin endpoint socket URI from the environment.
///
/// ## Errors
///
/// Returns [`DelegatedIdentityError`] if the environment variable is not set or the value is invalid.
pub fn admin_endpoint_from_env() -> Result<Endpoint, DelegatedIdentityError> {
    let raw =
        std::env::var_os(ADMIN_SOCKET_ENV).ok_or(DelegatedIdentityError::MissingEndpointSocket)?;
    if let Some(raw) = raw.to_str() {
        Ok(Endpoint::parse(raw)?)
    } else {
        Err(DelegatedIdentityError::NotUnicodeEndpointSocket(raw))
    }
}

/// Impl for `DelegatedIdentity` API
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
    /// Create a client by connecting to the given admin endpoint URI string (e.g. `unix:///...`).
    ///
    /// # Arguments
    ///
    /// * `endpoint` - The path to the UNIX domain socket, which can optionally start with "unix:".
    ///
    /// # Returns
    ///
    /// * `Result<Self, DelegatedIdentityError>` - Returns an instance of `DelegatedIdentityClient` if successful, otherwise returns an error.
    ///
    /// # Errors
    ///
    /// This function will return an error if the provided socket path is invalid or if there are issues connecting.
    pub async fn connect_to(endpoint: impl AsRef<str>) -> Result<Self, DelegatedIdentityError> {
        let endpoint = Endpoint::parse(endpoint.as_ref())?;
        Self::connect(endpoint).await
    }

    /// Creates a new `DelegatedIdentityClient` using the default socket endpoint address.
    ///
    /// Requires that the environment variable `SPIFFE_ENDPOINT_SOCKET` be set with
    /// the path to the Workload API endpoint socket.
    ///
    /// # Errors
    ///
    /// The function returns a variant of [`DelegatedIdentityError`] if environment variable is not set or if
    /// the provided socket path is not valid.
    pub async fn connect_env() -> Result<Self, DelegatedIdentityError> {
        let endpoint = admin_endpoint_from_env()?;
        Self::connect(endpoint).await
    }

    /// Create a client by connecting to a parsed SPIFFE [`Endpoint`].
    ///
    /// ## Errors
    ///
    /// Returns [`GrpcClientError`] if the connection fails or the endpoint is unsupported.
    pub async fn connect(endpoint: Endpoint) -> Result<Self, DelegatedIdentityError> {
        let channel = spiffe::transport::connector::connect(&endpoint).await?;
        Ok(Self {
            client: DelegatedIdentityApiClient::new(channel),
        })
    }

    /// Creates a new [`DelegatedIdentityClient`] from an established gRPC channel.
    ///
    /// This constructor does not perform any network I/O. It only wraps the
    /// provided [`tonic::transport::Channel`] and prepares the client for use.
    ///
    /// # Errors
    ///
    /// Returns [`DelegatedIdentityError`] if the client could not be constructed from
    /// the provided channel (for example, due to an invalid configuration).
    pub fn new(conn: tonic::transport::Channel) -> Result<Self, DelegatedIdentityError> {
        Ok(Self {
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
    /// If the fetch operation or the parsing fails, it returns a [`DelegatedIdentityError`].
    ///
    /// # Errors
    ///
    /// Returns [`DelegatedIdentityError`] if the gRPC call fails or if the SVID could not be parsed from the gRPC response.
    pub async fn fetch_x509_svid(
        &self,
        attest_type: DelegateAttestationRequest,
    ) -> Result<X509Svid, DelegatedIdentityError> {
        let request = make_x509svid_request(attest_type);

        self.client
            .clone()
            .subscribe_to_x509svi_ds(request)
            .await?
            .into_inner()
            .message()
            .await?
            .ok_or(DelegatedIdentityError::EmptyResponse)
            .and_then(|resp| Self::parse_x509_svid_from_grpc_response(&resp))
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
    /// Returns a stream of `Result<X509Svid, DelegatedIdentityError>`. Each item represents an updated [`X509Svid`] or an error if
    /// there was a problem processing an update from the stream.
    ///
    /// # Errors
    ///
    /// The function can return an error variant of [`DelegatedIdentityError`] in the following scenarios:
    ///
    /// * There's an issue connecting to the Workload API.
    /// * An error occurs while setting up the stream.
    ///
    /// Individual stream items might also be errors if there's an issue processing the response for a specific update.
    pub async fn stream_x509_svids(
        &self,
        attest_type: DelegateAttestationRequest,
    ) -> Result<
        impl Stream<Item = Result<X509Svid, DelegatedIdentityError>> + Send + '_,
        DelegatedIdentityError,
    > {
        let request = match attest_type {
            DelegateAttestationRequest::Selectors(selectors) => SubscribeToX509sviDsRequest {
                selectors: selectors.into_iter().map(Into::into).collect(),
                pid: 0,
            },
            DelegateAttestationRequest::Pid(pid) => SubscribeToX509sviDsRequest {
                selectors: Vec::new(),
                pid,
            },
        };

        let response = self.client.clone().subscribe_to_x509svi_ds(request).await?;

        let stream = response.into_inner().map(|message| {
            let resp = message.map_err(DelegatedIdentityError::from)?;
            Self::parse_x509_svid_from_grpc_response(&resp)
        });

        Ok(stream)
    }

    /// Fetches [`X509BundleSet`], that is a set of [`X509Bundle`] keyed by the trust domain to which they belong.
    ///
    /// # Errors
    ///
    /// The function returns a variant of [`DelegatedIdentityError`] if there is an error connecting to the Workload API or
    /// there is a problem processing the response.
    pub async fn fetch_x509_bundles(&self) -> Result<X509BundleSet, DelegatedIdentityError> {
        let request = SubscribeToX509BundlesRequest::default();

        let response = self
            .client
            .clone()
            .subscribe_to_x509_bundles(request)
            .await?;

        let initial = response
            .into_inner()
            .message()
            .await?
            .ok_or(DelegatedIdentityError::EmptyResponse)?;

        Self::parse_x509_bundle_set_from_grpc_response(initial)
    }

    /// Watches the stream of [`X509Bundle`] updates.
    ///
    /// This function establishes a stream with the Workload API to continuously receive updates for the [`X509Bundle`].
    /// The returned stream can be used to asynchronously yield new `X509Bundle` updates as they become available.
    ///
    /// # Returns
    ///
    /// Returns a stream of `Result<X509BundleSet, DelegatedIdentityError>`. Each item represents an updated [`X509BundleSet`] or an error if
    /// there was a problem processing an update from the stream.
    ///
    /// # Errors
    ///
    /// The function can return an error variant of [`DelegatedIdentityError`] in the following scenarios:
    ///
    /// * There's an issue connecting to the Admin API.
    /// * An error occurs while setting up the stream.
    ///
    /// Individual stream items might also be errors if there's an issue processing the response for a specific update.
    pub async fn stream_x509_bundles(
        &self,
    ) -> Result<
        impl Stream<Item = Result<X509BundleSet, DelegatedIdentityError>> + Send + 'static + use<>,
        DelegatedIdentityError,
    > {
        let request = SubscribeToX509BundlesRequest::default();

        let response = self
            .client
            .clone()
            .subscribe_to_x509_bundles(request)
            .await?;

        Ok(response.into_inner().map(|msg| {
            msg.map_err(DelegatedIdentityError::from)
                .and_then(Self::parse_x509_bundle_set_from_grpc_response)
        }))
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
    /// The function returns a variant of [`DelegatedIdentityError`] if there is an error connecting to the Workload API or
    /// there is a problem processing the response.
    pub async fn fetch_jwt_svids<T: AsRef<str> + Sync + ToString>(
        &self,
        audience: &[T],
        attest_type: DelegateAttestationRequest,
    ) -> Result<Vec<JwtSvid>, DelegatedIdentityError> {
        let request = make_jwtsvid_request(audience, attest_type);

        let resp = self
            .client
            .clone()
            .fetch_jwtsvi_ds(request)
            .await?
            .into_inner()
            .svids;

        Self::parse_jwt_svid_from_grpc_response(resp)
    }

    /// Watches the stream of [`JwtBundleSet`] updates.
    ///
    /// This function establishes a stream with the Workload API to continuously receive updates for the [`JwtBundleSet`].
    /// The returned stream can be used to asynchronously yield new `JwtBundleSet` updates as they become available.
    ///
    /// # Returns
    ///
    /// Returns a stream of `Result<JwtBundleSet, DelegatedIdentityError>`. Each item represents an updated [`JwtBundleSet`] or an error if
    /// there was a problem processing an update from the stream.
    ///
    /// # Errors
    ///
    /// The function can return an error variant of [`DelegatedIdentityError`] in the following scenarios:
    ///
    /// * There's an issue connecting to the Workload API.
    /// * An error occurs while setting up the stream.
    ///
    /// Individual stream items might also be errors if there's an issue processing the response for a specific update.
    pub async fn stream_jwt_bundles(
        &self,
    ) -> Result<
        impl Stream<Item = Result<JwtBundleSet, DelegatedIdentityError>> + Send + 'static + use<>,
        DelegatedIdentityError,
    > {
        let request = SubscribeToJwtBundlesRequest::default();

        let response = self
            .client
            .clone()
            .subscribe_to_jwt_bundles(request)
            .await?;

        Ok(response.into_inner().map(|msg| {
            msg.map_err(DelegatedIdentityError::from)
                .and_then(Self::parse_jwt_bundle_set_from_grpc_response)
        }))
    }

    /// Fetches [`JwtBundleSet`] that is a set of [`JwtBundle`] keyed by the trust domain to which they belong.
    ///
    /// # Errors
    ///
    /// The function returns a variant of [`DelegatedIdentityError`] if there is an error connecting to the Workload API or
    /// there is a problem processing the response.
    pub async fn fetch_jwt_bundles(&self) -> Result<JwtBundleSet, DelegatedIdentityError> {
        let request = SubscribeToJwtBundlesRequest::default();

        let response = self
            .client
            .clone()
            .subscribe_to_jwt_bundles(request)
            .await?;

        let initial = response
            .into_inner()
            .message()
            .await?
            .ok_or(DelegatedIdentityError::EmptyResponse)?;

        Self::parse_jwt_bundle_set_from_grpc_response(initial)
    }
}

impl DelegatedIdentityClient {
    fn parse_x509_svid_from_grpc_response(
        response: &SubscribeToX509sviDsResponse,
    ) -> Result<X509Svid, DelegatedIdentityError> {
        let svid = response
            .x509_svids
            .get(DEFAULT_SVID)
            .ok_or(DelegatedIdentityError::EmptyResponse)?;

        let x509_svid = svid
            .x509_svid
            .as_ref()
            .ok_or(DelegatedIdentityError::EmptyResponse)?;

        let total_length: usize = x509_svid
            .cert_chain
            .iter()
            .map(prost::bytes::Bytes::len)
            .sum();
        let mut cert_chain_bytes = Vec::with_capacity(total_length);
        for c in &x509_svid.cert_chain {
            cert_chain_bytes.extend_from_slice(c);
        }

        X509Svid::parse_from_der(&cert_chain_bytes, svid.x509_svid_key.as_ref()).map_err(Into::into)
    }

    fn parse_jwt_svid_from_grpc_response(
        svids: Vec<ProtoJwtSvid>,
    ) -> Result<Vec<JwtSvid>, DelegatedIdentityError> {
        svids
            .into_iter()
            .map(|r| JwtSvid::from_str(&r.token).map_err(DelegatedIdentityError::from))
            .collect()
    }

    fn parse_jwt_bundle_set_from_grpc_response(
        response: SubscribeToJwtBundlesResponse,
    ) -> Result<JwtBundleSet, DelegatedIdentityError> {
        let mut bundle_set = JwtBundleSet::new();

        for (td, bundle_data) in response.bundles {
            let trust_domain = TrustDomain::try_from(td)?;
            let bundle = JwtBundle::from_jwt_authorities(trust_domain, &bundle_data)
                .map_err(DelegatedIdentityError::from)?;
            bundle_set.add_bundle(bundle);
        }

        Ok(bundle_set)
    }

    fn parse_x509_bundle_set_from_grpc_response(
        response: SubscribeToX509BundlesResponse,
    ) -> Result<X509BundleSet, DelegatedIdentityError> {
        let mut bundle_set = X509BundleSet::new();

        for (td, bundle) in response.ca_certificates {
            let trust_domain = TrustDomain::try_from(td)?;
            let parsed = X509Bundle::parse_from_der(trust_domain, &bundle)
                .map_err(DelegatedIdentityError::from)?;
            bundle_set.add_bundle(parsed);
        }

        Ok(bundle_set)
    }
}

// Error conversions
impl From<tonic::Status> for DelegatedIdentityError {
    fn from(status: tonic::Status) -> Self {
        Self::Transport(TransportError::Status(status))
    }
}

impl From<tonic::transport::Error> for DelegatedIdentityError {
    fn from(err: tonic::transport::Error) -> Self {
        Self::Transport(TransportError::Tonic(err))
    }
}

fn make_x509svid_request(attest_type: DelegateAttestationRequest) -> SubscribeToX509sviDsRequest {
    match attest_type {
        DelegateAttestationRequest::Selectors(selectors) => SubscribeToX509sviDsRequest {
            selectors: selectors.into_iter().map(Into::into).collect(),
            pid: 0,
        },
        DelegateAttestationRequest::Pid(pid) => SubscribeToX509sviDsRequest {
            selectors: Vec::new(),
            pid,
        },
    }
}

fn make_jwtsvid_request<T: AsRef<str> + ToString>(
    audience: &[T],
    attest_type: DelegateAttestationRequest,
) -> FetchJwtsviDsRequest {
    let audience = audience.iter().map(ToString::to_string).collect();

    match attest_type {
        DelegateAttestationRequest::Selectors(selectors) => FetchJwtsviDsRequest {
            audience,
            selectors: selectors.into_iter().map(Into::into).collect(),
            pid: 0,
        },
        DelegateAttestationRequest::Pid(pid) => FetchJwtsviDsRequest {
            audience,
            selectors: Vec::new(),
            pid,
        },
    }
}
