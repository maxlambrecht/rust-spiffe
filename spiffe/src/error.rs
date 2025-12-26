//! Error types for Workload API client operations.

use crate::endpoint::EndpointError;
use crate::{JwtBundleError, JwtSvidError, SpiffeIdError, X509BundleError, X509SvidError};
use thiserror::Error;
use url::ParseError;

/// Errors produced by the Workload API client.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum GrpcClientError {
    /// `SPIFFE_ENDPOINT_SOCKET` is not set.
    #[error("missing SPIFFE endpoint socket path (SPIFFE_ENDPOINT_SOCKET)")]
    MissingEndpointSocket,

    /// The Workload API returned an empty response.
    #[error("empty Workload API response")]
    EmptyResponse,

    /// The endpoint socket value is invalid.
    #[error("invalid endpoint socket path")]
    InvalidEndpointSocket(#[from] SocketPathError),

    /// Failed to parse an X.509 SVID from the Workload API response.
    #[error("x509 svid parse error")]
    X509Svid(#[from] X509SvidError),

    /// Failed to parse a JWT-SVID from the Workload API response.
    #[error("jwt svid parse error")]
    JwtSvid(#[from] JwtSvidError),

    /// Failed to parse an X.509 bundle from the Workload API response.
    #[error("x509 bundle parse error")]
    X509Bundle(#[from] X509BundleError),

    /// Failed to parse a JWT bundle from the Workload API response.
    #[error("jwt bundle parse error")]
    JwtBundle(#[from] JwtBundleError),

    /// Failed to parse a SPIFFE identifier from the Workload API response.
    #[error("spiffe id parse error")]
    SpiffeId(#[from] SpiffeIdError),

    /// The Workload API denied issuing an identity for this workload (e.g. selectors do not match).
    #[error("no identity issued")]
    NoIdentityIssued,

    /// The Workload API denied the request for other permission reasons.
    #[error("permission denied: {0}")]
    PermissionDenied(String),

    /// Failed to parse the Workload API endpoint string.
    #[cfg(feature = "workload-api")]
    #[error("invalid workload api endpoint: {0}")]
    Endpoint(#[from] EndpointError),

    /// The endpoint transport is unsupported on the current platform.
    #[error("unsupported endpoint transport: {scheme}")]
    UnsupportedEndpointTransport {
        /// The unsupported transport scheme.
        scheme: &'static str,
    },

    /// gRPC status returned by the Workload API.
    #[cfg(feature = "workload-api")]
    #[error("gRPC status: {0}")]
    Grpc(#[source] tonic::Status),

    /// Transport error while connecting to the Workload API.
    #[cfg(feature = "workload-api")]
    #[error("gRPC transport error: {0}")]
    Transport(#[from] tonic::transport::Error),
}

#[cfg(feature = "workload-api")]
impl From<tonic::Status> for GrpcClientError {
    fn from(status: tonic::Status) -> Self {
        use tonic::Code;

        // SPIRE typically uses PermissionDenied + "no identity issued" when selectors don't match.
        // We special-case it to expose a stable, matchable semantic error to library users.
        if status.code() == Code::PermissionDenied {
            let msg = status.message();

            if msg.contains("no identity issued") {
                return GrpcClientError::NoIdentityIssued;
            }

            return GrpcClientError::PermissionDenied(msg.to_owned());
        }

        GrpcClientError::Grpc(status)
    }
}

/// Errors related to validating `SPIFFE_ENDPOINT_SOCKET`.
#[derive(Debug, Error, PartialEq, Clone)]
#[non_exhaustive]
pub enum SocketPathError {
    /// Scheme must be `unix` or `tcp`.
    #[error("endpoint socket URI scheme must be tcp: or unix:")]
    InvalidScheme,

    /// `unix://` URIs must include a path.
    #[error("unix:// endpoint socket URI must include a path")]
    UnixAddressEmptyPath,

    /// `tcp://` URIs must not include a path component.
    #[error("tcp:// endpoint socket URI must not include a path")]
    TcpAddressNonEmptyPath,

    /// URI must not include query values.
    #[error("endpoint socket URI must not include query values")]
    HasQueryValues,

    /// URI must not include a fragment.
    #[error("endpoint socket URI must not include a fragment")]
    HasFragment,

    /// URI must not include user info.
    #[error("endpoint socket URI must not include user info")]
    HasUserInfo,

    /// `tcp://` URIs must include a host.
    #[error("tcp:// endpoint socket URI must include a host")]
    TcpEmptyHost,

    /// `tcp://` URI host must be an IP address.
    #[error("tcp:// endpoint socket URI host must be an IP address")]
    TcpHostNotIp,

    /// `tcp://` URIs must include a port.
    #[error("tcp:// endpoint socket URI must include a port")]
    TcpMissingPort,

    /// URI parsing failed.
    #[error("endpoint socket is not a valid URI")]
    Parse(#[from] ParseError),
}
