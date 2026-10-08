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
use spiffe::transport::{Endpoint, GrpcStatusCode, TransportError};
use spiffe::{
    JwtBundle, JwtBundleError, JwtBundleSet, JwtSvid, JwtSvidError, SpiffeIdError, TrustDomain,
    X509Bundle, X509BundleError, X509BundleSet, X509Svid, X509SvidError,
};

use std::str::FromStr as _;
use std::sync::Arc;

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

    /// The delegated attestation request is invalid.
    #[error(transparent)]
    InvalidRequest(#[from] DelegateAttestationRequestError),
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
#[non_exhaustive]
pub enum DelegateAttestationRequest {
    /// PID (let agent attest PID->selectors)
    Pid(DelegatePid),
    /// selectors (delegate has already attested a PID and generated full set of selectors)
    Selectors(DelegateSelectors),
}

impl DelegateAttestationRequest {
    /// Creates an attestation request for a positive process ID.
    ///
    /// Accepts values in `1..=i32::MAX`. For the wider range supported by PID
    /// selectors, see [`UnixPid`](crate::selectors::UnixPid).
    ///
    /// # Errors
    ///
    /// Returns [`DelegateAttestationRequestError::PidOutOfRange`] when `pid` is
    /// outside `1..=i32::MAX`.
    pub fn for_pid(pid: u32) -> Result<Self, DelegateAttestationRequestError> {
        Ok(Self::Pid(DelegatePid::try_from(pid)?))
    }

    /// Creates an attestation request from a non-empty selector list.
    ///
    /// # Errors
    ///
    /// Returns [`DelegateAttestationRequestError::EmptySelectors`] when no
    /// selectors are supplied.
    pub fn for_selectors(
        selectors: Vec<Selector>,
    ) -> Result<Self, DelegateAttestationRequestError> {
        Ok(Self::Selectors(DelegateSelectors::try_from(selectors)?))
    }
}

/// A process ID in `1..=i32::MAX` for delegated attestation.
///
/// The Delegated Identity API uses a signed 32-bit PID field. For PID selectors
/// with a wider range, see [`UnixPid`](crate::selectors::UnixPid).
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct DelegatePid(i32);

impl DelegatePid {
    /// Returns the numeric process ID.
    pub const fn get(self) -> i32 {
        self.0
    }
}

impl TryFrom<u32> for DelegatePid {
    type Error = DelegateAttestationRequestError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if value == 0 {
            return Err(DelegateAttestationRequestError::PidOutOfRange(value));
        }
        i32::try_from(value)
            .map(Self)
            .map_err(|_range_error| DelegateAttestationRequestError::PidOutOfRange(value))
    }
}

/// A non-empty selector list for delegated attestation.
#[derive(Debug, Clone)]
pub struct DelegateSelectors(Vec<Selector>);

impl DelegateSelectors {
    fn into_vec(self) -> Vec<Selector> {
        self.0
    }

    /// Returns the selectors in this request.
    pub fn as_slice(&self) -> &[Selector] {
        &self.0
    }
}

impl TryFrom<Vec<Selector>> for DelegateSelectors {
    type Error = DelegateAttestationRequestError;

    fn try_from(value: Vec<Selector>) -> Result<Self, Self::Error> {
        if value.is_empty() {
            Err(DelegateAttestationRequestError::EmptySelectors)
        } else {
            Ok(Self(value))
        }
    }
}

/// Errors encountered when validating delegated attestation or JWT-SVID requests.
#[derive(Debug, Clone, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum DelegateAttestationRequestError {
    /// The process ID is outside `1..=i32::MAX`.
    #[error("delegated PID {0} is outside the supported range 1..={max}", max = i32::MAX)]
    PidOutOfRange(u32),
    /// The selector list is empty.
    #[error("delegated attestation selector list must not be empty")]
    EmptySelectors,
    /// The audience list is empty or contains an empty value.
    #[error("JWT-SVID audience must contain at least one non-empty value")]
    EmptyAudience,
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
    /// Requires that [`ADMIN_SOCKET_ENV`] (`SPIRE_ADMIN_ENDPOINT_SOCKET`) be set
    /// to the SPIRE Agent Admin API endpoint socket.
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
    /// Returns [`DelegatedIdentityError`] if the connection fails or the endpoint is unsupported.
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
    pub fn new(conn: tonic::transport::Channel) -> Self {
        Self {
            client: DelegatedIdentityApiClient::new(conn),
        }
    }
}

impl DelegatedIdentityClient {
    /// Fetches a single X509 SPIFFE Verifiable Identity Document (SVID).
    ///
    /// This method calls the SPIRE Agent Admin API and returns the first X509 SVID in the response.
    ///
    /// # Arguments
    ///
    /// * `attest_type` - A validated PID or selector request identifying the workload to attest.
    ///
    /// # Returns
    ///
    /// On success, it returns a valid [`X509Svid`] which represents the parsed SVID.
    /// A non-empty usage hint from the API is preserved on the returned SVID
    /// (via [`X509Svid::hint`]); an empty hint is mapped to [`None`].
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
            .await
            .map_err(status_error)?
            .into_inner()
            .message()
            .await
            .map_err(status_error)?
            .ok_or(DelegatedIdentityError::EmptyResponse)
            .and_then(|resp| Self::parse_x509_svid_from_grpc_response(&resp))
    }

    /// Watches the stream of [`X509Svid`] updates.
    ///
    /// This function establishes a stream with the Agent Admin API to continuously receive updates for the [`X509Svid`].
    /// The returned stream can be used to asynchronously yield new `X509Svid` updates as they become available.
    ///
    /// # Arguments
    ///
    /// * `attest_type` - A validated PID or selector request identifying the workload to attest.
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
    /// * There's an issue connecting to the Agent Admin API.
    /// * An error occurs while setting up the stream.
    ///
    /// Individual stream items might also be errors if there's an issue processing the response for a specific update.
    pub async fn stream_x509_svids(
        &self,
        attest_type: DelegateAttestationRequest,
    ) -> Result<
        impl Stream<Item = Result<X509Svid, DelegatedIdentityError>> + Send + 'static + use<>,
        DelegatedIdentityError,
    > {
        let request = match attest_type {
            DelegateAttestationRequest::Selectors(selectors) => SubscribeToX509sviDsRequest {
                selectors: selectors.into_vec().into_iter().map(Into::into).collect(),
                pid: 0,
            },
            DelegateAttestationRequest::Pid(pid) => SubscribeToX509sviDsRequest {
                selectors: Vec::new(),
                pid: pid.get(),
            },
        };

        let response = self
            .client
            .clone()
            .subscribe_to_x509svi_ds(request)
            .await
            .map_err(status_error)?;

        let stream = response.into_inner().map(|message| {
            let resp = message.map_err(status_error)?;
            Self::parse_x509_svid_from_grpc_response(&resp)
        });

        Ok(stream)
    }

    /// Fetches [`X509BundleSet`], that is a set of [`X509Bundle`] keyed by the trust domain to which they belong.
    ///
    /// # Errors
    ///
    /// The function returns a variant of [`DelegatedIdentityError`] if there is an error connecting to the Agent Admin API or
    /// there is a problem processing the response.
    pub async fn fetch_x509_bundles(&self) -> Result<X509BundleSet, DelegatedIdentityError> {
        let request = SubscribeToX509BundlesRequest::default();

        let response = self
            .client
            .clone()
            .subscribe_to_x509_bundles(request)
            .await
            .map_err(status_error)?;

        let initial = response
            .into_inner()
            .message()
            .await
            .map_err(status_error)?
            .ok_or(DelegatedIdentityError::EmptyResponse)?;

        Self::parse_x509_bundle_set_from_grpc_response(initial)
    }

    /// Watches the stream of [`X509Bundle`] updates.
    ///
    /// This function establishes a stream with the Agent Admin API to continuously receive updates for the [`X509Bundle`].
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
            .await
            .map_err(status_error)?;

        Ok(response.into_inner().map(|msg| {
            msg.map_err(status_error)
                .and_then(Self::parse_x509_bundle_set_from_grpc_response)
        }))
    }

    /// Fetches a list of [`JwtSvid`] parsing the JWT tokens in the Delegated Identity
    /// response, for the given audience and attestation request.
    ///
    /// Each returned [`JwtSvid`] may include an optional usage hint (via [`JwtSvid::hint`])
    /// that can be used to disambiguate which SVID to use when multiple identities are
    /// returned. Empty hints from the API are mapped to [`None`].
    ///
    /// # Arguments
    ///
    /// * `audience`  - A non-empty list of non-empty audiences to include in the JWT token.
    /// * `attest_type` - PID or selectors identifying the workload to attest.
    ///
    /// # Errors
    ///
    /// Returns [`DelegatedIdentityError::InvalidRequest`] containing
    /// [`DelegateAttestationRequestError::EmptyAudience`] if the audience list is
    /// empty or contains an empty value. This validation occurs before contacting
    /// the API. Errors also occur if the API request fails or the response cannot
    /// be parsed.
    pub async fn fetch_jwt_svids<T: AsRef<str> + Sync + ToString>(
        &self,
        audience: &[T],
        attest_type: DelegateAttestationRequest,
    ) -> Result<Vec<JwtSvid>, DelegatedIdentityError> {
        let request = make_jwtsvid_request(audience, attest_type)?;

        let resp = self
            .client
            .clone()
            .fetch_jwtsvi_ds(request)
            .await
            .map_err(status_error)?
            .into_inner()
            .svids;

        Self::parse_jwt_svid_from_grpc_response(resp)
    }

    /// Watches the stream of [`JwtBundleSet`] updates.
    ///
    /// This function establishes a stream with the Agent Admin API to continuously receive updates for the [`JwtBundleSet`].
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
    /// * There's an issue connecting to the Agent Admin API.
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
            .await
            .map_err(status_error)?;

        Ok(response.into_inner().map(|msg| {
            msg.map_err(status_error)
                .and_then(Self::parse_jwt_bundle_set_from_grpc_response)
        }))
    }

    /// Fetches [`JwtBundleSet`] that is a set of [`JwtBundle`] keyed by the trust domain to which they belong.
    ///
    /// # Errors
    ///
    /// The function returns a variant of [`DelegatedIdentityError`] if there is an error connecting to the Agent Admin API or
    /// there is a problem processing the response.
    pub async fn fetch_jwt_bundles(&self) -> Result<JwtBundleSet, DelegatedIdentityError> {
        let request = SubscribeToJwtBundlesRequest::default();

        let response = self
            .client
            .clone()
            .subscribe_to_jwt_bundles(request)
            .await
            .map_err(status_error)?;

        let initial = response
            .into_inner()
            .message()
            .await
            .map_err(status_error)?
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

        let hint = (!x509_svid.hint.is_empty()).then(|| Arc::<str>::from(x509_svid.hint.as_str()));

        X509Svid::parse_from_der_with_hint(&cert_chain_bytes, svid.x509_svid_key.as_ref(), hint)
            .map_err(Into::into)
    }

    fn parse_jwt_svid_from_grpc_response(
        svids: Vec<ProtoJwtSvid>,
    ) -> Result<Vec<JwtSvid>, DelegatedIdentityError> {
        svids
            .into_iter()
            .map(|r| {
                let mut svid = JwtSvid::from_str(&r.token)?;
                if !r.hint.is_empty() {
                    svid = svid.with_hint(Arc::<str>::from(r.hint));
                }
                Ok(svid)
            })
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

fn status_error(status: tonic::Status) -> DelegatedIdentityError {
    let code = grpc_status_code(status.code());
    let message = status.message().to_owned();
    DelegatedIdentityError::Transport(TransportError::status_with_source(code, message, status))
}

const fn grpc_status_code(code: tonic::Code) -> GrpcStatusCode {
    match code {
        tonic::Code::Ok => GrpcStatusCode::Ok,
        tonic::Code::Cancelled => GrpcStatusCode::Cancelled,
        tonic::Code::Unknown => GrpcStatusCode::Unknown,
        tonic::Code::InvalidArgument => GrpcStatusCode::InvalidArgument,
        tonic::Code::DeadlineExceeded => GrpcStatusCode::DeadlineExceeded,
        tonic::Code::NotFound => GrpcStatusCode::NotFound,
        tonic::Code::AlreadyExists => GrpcStatusCode::AlreadyExists,
        tonic::Code::PermissionDenied => GrpcStatusCode::PermissionDenied,
        tonic::Code::ResourceExhausted => GrpcStatusCode::ResourceExhausted,
        tonic::Code::FailedPrecondition => GrpcStatusCode::FailedPrecondition,
        tonic::Code::Aborted => GrpcStatusCode::Aborted,
        tonic::Code::OutOfRange => GrpcStatusCode::OutOfRange,
        tonic::Code::Unimplemented => GrpcStatusCode::Unimplemented,
        tonic::Code::Internal => GrpcStatusCode::Internal,
        tonic::Code::Unavailable => GrpcStatusCode::Unavailable,
        tonic::Code::DataLoss => GrpcStatusCode::DataLoss,
        tonic::Code::Unauthenticated => GrpcStatusCode::Unauthenticated,
    }
}

fn make_x509svid_request(attest_type: DelegateAttestationRequest) -> SubscribeToX509sviDsRequest {
    match attest_type {
        DelegateAttestationRequest::Selectors(selectors) => SubscribeToX509sviDsRequest {
            selectors: selectors.into_vec().into_iter().map(Into::into).collect(),
            pid: 0,
        },
        DelegateAttestationRequest::Pid(pid) => SubscribeToX509sviDsRequest {
            selectors: Vec::new(),
            pid: pid.get(),
        },
    }
}

fn make_jwtsvid_request<T: AsRef<str> + ToString>(
    audience: &[T],
    attest_type: DelegateAttestationRequest,
) -> Result<FetchJwtsviDsRequest, DelegateAttestationRequestError> {
    let audience: Vec<_> = audience.iter().map(ToString::to_string).collect();
    if audience.is_empty() || audience.iter().any(String::is_empty) {
        return Err(DelegateAttestationRequestError::EmptyAudience);
    }

    Ok(match attest_type {
        DelegateAttestationRequest::Selectors(selectors) => FetchJwtsviDsRequest {
            audience,
            selectors: selectors.into_vec().into_iter().map(Into::into).collect(),
            pid: 0,
        },
        DelegateAttestationRequest::Pid(pid) => FetchJwtsviDsRequest {
            audience,
            selectors: Vec::new(),
            pid: pid.get(),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pb::spire::api::agent::delegatedidentity::v1::X509svidWithKey;
    use crate::pb::spire::api::types::X509svid as ProtoX509Svid;

    const JWT_TOKEN: &str = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImsxIiwidHlwIjoiSldUIn0.eyJzdWIiOiJzcGlmZmU6Ly9leGFtcGxlLm9yZy9zZXJ2aWNlIiwiYXVkIjoiYXVkMSIsImV4cCI6NDI5NDk2NzI5NX0.sig";

    fn delegated_x509_response(hint: &str) -> SubscribeToX509sviDsResponse {
        SubscribeToX509sviDsResponse {
            x509_svids: vec![X509svidWithKey {
                x509_svid: Some(ProtoX509Svid {
                    cert_chain: vec![prost::bytes::Bytes::from_static(include_bytes!(
                        "../../tests/testdata/svid/x509/1-svid-chain.der"
                    ))],
                    hint: hint.to_owned(),
                    ..Default::default()
                }),
                x509_svid_key: prost::bytes::Bytes::from_static(include_bytes!(
                    "../../tests/testdata/svid/x509/1-key.der"
                )),
            }],
            ..Default::default()
        }
    }

    #[test]
    fn delegated_x509_svid_preserves_non_empty_hint() {
        let response = delegated_x509_response("internal");

        let svid = DelegatedIdentityClient::parse_x509_svid_from_grpc_response(&response)
            .expect("delegated X.509 SVID should parse");

        assert_eq!(svid.hint(), Some("internal"));
    }

    #[test]
    fn delegated_x509_svid_maps_empty_hint_to_none() {
        let response = delegated_x509_response("");

        let svid = DelegatedIdentityClient::parse_x509_svid_from_grpc_response(&response)
            .expect("delegated X.509 SVID should parse");

        assert_eq!(svid.hint(), None);
    }

    #[test]
    fn delegated_jwt_svids_preserve_order_and_hints() {
        let svids = DelegatedIdentityClient::parse_jwt_svid_from_grpc_response(vec![
            ProtoJwtSvid {
                token: JWT_TOKEN.to_owned(),
                hint: "internal".to_owned(),
                ..Default::default()
            },
            ProtoJwtSvid {
                token: JWT_TOKEN.to_owned(),
                hint: "external".to_owned(),
                ..Default::default()
            },
            ProtoJwtSvid {
                token: JWT_TOKEN.to_owned(),
                hint: String::new(),
                ..Default::default()
            },
        ])
        .expect("delegated JWT SVIDs should parse");

        assert_eq!(svids.len(), 3);
        assert_eq!(
            svids.first().expect("first JWT-SVID").hint(),
            Some("internal")
        );
        assert_eq!(
            svids.get(1).expect("second JWT-SVID").hint(),
            Some("external")
        );
        assert_eq!(svids.get(2).expect("third JWT-SVID").hint(), None);
    }

    #[test]
    fn tonic_status_keeps_its_code_and_message() {
        let cases = [
            (tonic::Code::Ok, GrpcStatusCode::Ok),
            (tonic::Code::Cancelled, GrpcStatusCode::Cancelled),
            (tonic::Code::Unknown, GrpcStatusCode::Unknown),
            (
                tonic::Code::InvalidArgument,
                GrpcStatusCode::InvalidArgument,
            ),
            (
                tonic::Code::DeadlineExceeded,
                GrpcStatusCode::DeadlineExceeded,
            ),
            (tonic::Code::NotFound, GrpcStatusCode::NotFound),
            (tonic::Code::AlreadyExists, GrpcStatusCode::AlreadyExists),
            (
                tonic::Code::PermissionDenied,
                GrpcStatusCode::PermissionDenied,
            ),
            (
                tonic::Code::ResourceExhausted,
                GrpcStatusCode::ResourceExhausted,
            ),
            (
                tonic::Code::FailedPrecondition,
                GrpcStatusCode::FailedPrecondition,
            ),
            (tonic::Code::Aborted, GrpcStatusCode::Aborted),
            (tonic::Code::OutOfRange, GrpcStatusCode::OutOfRange),
            (tonic::Code::Unimplemented, GrpcStatusCode::Unimplemented),
            (tonic::Code::Internal, GrpcStatusCode::Internal),
            (tonic::Code::Unavailable, GrpcStatusCode::Unavailable),
            (tonic::Code::DataLoss, GrpcStatusCode::DataLoss),
            (
                tonic::Code::Unauthenticated,
                GrpcStatusCode::Unauthenticated,
            ),
        ];

        for (tonic_code, expected) in cases {
            let status = tonic::Status::new(tonic_code, "detail");
            let err = status_error(status);
            let DelegatedIdentityError::Transport(transport) = err else {
                panic!("{tonic_code:?} should remain a transport error");
            };
            let TransportError::Status(grpc) = transport else {
                panic!("{tonic_code:?} should remain a gRPC status");
            };

            assert_eq!(grpc.code(), expected);
            assert_eq!(grpc.message(), "detail");
            assert!(std::error::Error::source(&grpc)
                .expect("original status")
                .to_string()
                .contains("detail"));
        }
    }

    #[test]
    fn delegated_status_retains_details_metadata_and_nested_cause() {
        use std::error::Error as _;

        let mut status = tonic::Status::with_details(
            tonic::Code::Unavailable,
            "agent unavailable",
            b"diagnostic details".as_slice().into(),
        );
        status
            .metadata_mut()
            .insert("diagnostic", "context".parse().unwrap());
        status.set_source(Arc::new(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "admin socket refused",
        )));
        let err = status_error(status);
        let source = err.source().expect("transport diagnostic source");
        // Downcasting here verifies retention internally; consumers use the owned
        // code/message for behavior and the error chain for diagnostics.
        let status = source
            .downcast_ref::<tonic::Status>()
            .expect("original status");
        assert_eq!(status.details(), b"diagnostic details");
        assert_eq!(status.metadata().get("diagnostic").unwrap(), "context");
        assert_eq!(
            source.source().expect("nested cause").to_string(),
            "admin socket refused"
        );
    }

    #[test]
    fn delegated_request_rejects_invalid_protocol_states() {
        assert_eq!(
            DelegateAttestationRequest::for_pid(0).unwrap_err(),
            DelegateAttestationRequestError::PidOutOfRange(0)
        );
        assert_eq!(
            DelegateAttestationRequest::for_pid(i32::MAX as u32 + 1).unwrap_err(),
            DelegateAttestationRequestError::PidOutOfRange(i32::MAX as u32 + 1)
        );
        assert_eq!(
            DelegateAttestationRequest::for_selectors(Vec::new()).unwrap_err(),
            DelegateAttestationRequestError::EmptySelectors
        );
        assert_eq!(
            make_jwtsvid_request(&["", ""], DelegateAttestationRequest::for_pid(1).unwrap())
                .unwrap_err(),
            DelegateAttestationRequestError::EmptyAudience
        );
        assert_eq!(
            make_jwtsvid_request(
                &["payments", ""],
                DelegateAttestationRequest::for_pid(1).unwrap()
            )
            .unwrap_err(),
            DelegateAttestationRequestError::EmptyAudience
        );
    }
}
