//! Error types for Workload API client operations.

use crate::{JwtBundleError, JwtSvidError, SpiffeIdError, X509BundleError, X509SvidError};
use thiserror::Error;
use url::ParseError;

/// Errors produced by the Workload API client.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum GrpcClientError {
    /// `SPIFFE_ENDPOINT_SOCKET` is not set.
    #[error("missing SPIFFE_ENDPOINT_SOCKET")]
    MissingEndpointSocketPath,

    /// The Workload API returned an empty response.
    #[error("empty Workload API response")]
    EmptyResponse,

    /// The endpoint socket path is invalid.
    #[error("invalid endpoint socket path")]
    InvalidEndpointSocketPath(#[from] SocketPathError),

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

    /// gRPC status returned by the Workload API.
    #[cfg(feature = "workload-api")]
    #[error("gRPC status: {0}")]
    Grpc(#[from] tonic::Status),

    /// Transport error while connecting to the Workload API.
    #[cfg(feature = "workload-api")]
    #[error("gRPC transport error: {0}")]
    Transport(#[from] tonic::transport::Error),
}

/// Errors related to validating `SPIFFE_ENDPOINT_SOCKET`.
#[derive(Debug, Error, PartialEq, Clone)]
#[non_exhaustive]
pub enum SocketPathError {
    /// Scheme must be `unix` or `tcp`.
    #[error("endpoint socket URI scheme must be tcp:// or unix://")]
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

    /// `tcp://` URIs must include an IP:port.
    #[error("tcp:// endpoint socket URI host must be an IP:port")]
    TcpAddressNoIpPort,

    /// URI parsing failed.
    #[error("endpoint socket is not a valid URI")]
    Parse(#[from] ParseError),
}
