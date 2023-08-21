//! Defines errors related to interactions with the GRPC client, including handling of X.509 and JWT materials,
//! SPIFFE endpoint socket path validation, and other potential failure points within the Rust-Spiffe library.
//! This encompasses errors related to endpoint configuration, response handling, data processing, and specific
//! errors for various SPIFFE components.

use crate::bundle::jwt::JwtBundleError;
use crate::bundle::x509::X509BundleError;
use crate::spiffe_id::SpiffeIdError;
use crate::svid::jwt::JwtSvidError;
use crate::svid::x509::X509SvidError;
use thiserror::Error;
use url::ParseError;

/// Errors that may arise while interacting with and fetching materials from a GRPC client.
/// Includes errors related to endpoint configuration, response handling, and data processing.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum GrpcClientError {
    /// Missing environment variable for the endpoint socket address.
    #[error("missing endpoint socket address environment variable (SPIFFE_ENDPOINT_SOCKET)")]
    MissingEndpointSocketPath,

    /// The GRPC client received an empty response.
    #[error("received an empty response from the GRPC client")]
    EmptyResponse,

    /// Invalid endpoint socket path configuration.
    #[error("invalid endpoint socket path")]
    InvalidEndpointSocketPath(#[from] SocketPathError),

    /// Failed to parse the X509Svid response from the client.
    #[error("failed to process X509Svid response")]
    InvalidX509Svid(#[from] X509SvidError),

    /// Failed to parse the JwtSvid response from the client.
    #[error("failed to process JwtSvid response")]
    InvalidJwtSvid(#[from] JwtSvidError),

    /// Failed to parse the X509Bundle response from the client.
    #[error("failed to process X509Bundle response")]
    InvalidX509Bundle(#[from] X509BundleError),

    /// Failed to parse the JwtBundle response from the client.
    #[error("failed to process JwtBundle response")]
    InvalidJwtBundle(#[from] JwtBundleError),

    /// Invalid trust domain in the bundles response.
    #[error("invalid trust domain in bundles response")]
    InvalidTrustDomain(#[from] SpiffeIdError),

    /// Error returned by the GRPC library for error responses from the client.
    #[error("error response from the GRPC client")]
    Grpc(#[from] tonic::Status),

    /// Error returned by the GRPC library when creating a transport channel.
    #[error("error creating transport channel to the GRPC client")]
    Transport(#[from] tonic::transport::Error),
}

/// Errors related to the validation of a SPIFFE endpoint socket path.
/// These cover scenarios such as invalid URI schemes, missing components, and unexpected URI structure.
#[derive(Debug, Error, PartialEq, Copy, Clone)]
#[non_exhaustive]
pub enum SocketPathError {
    /// The SPIFFE endpoint socket URI has a scheme other than 'unix' or 'tcp'.
    #[error("workload endpoint socket URI must have a tcp:// or unix:// scheme")]
    InvalidScheme,

    /// The SPIFFE endpoint unix socket URI does not include a path.
    #[error("workload endpoint unix socket URI must include a path")]
    UnixAddressEmptyPath,

    /// The SPIFFE endpoint tcp socket URI include a path.
    #[error("workload endpoint tcp socket URI must not include a path")]
    TcpAddressNonEmptyPath,

    /// The SPIFFE endpoint socket URI has query values.
    #[error("workload endpoint socket URI must not include query values")]
    HasQueryValues,

    /// The SPIFFE endpoint socket URI has a fragment.
    #[error("workload endpoint socket URI must not include a fragment")]
    HasFragment,

    /// The SPIFFE endpoint socket URI has query user info.
    #[error("workload endpoint socket URI must not include user info")]
    HasUserInfo,

    /// The SPIFFE endpoint tcp socket URI has misses a host.
    #[error("workload endpoint tcp socket URI must include a host")]
    TcpEmptyHost,

    /// The SPIFFE endpoint tcp socket URI has misses a port.
    #[error("workload endpoint tcp socket URI host component must be an IP:port")]
    TcpAddressNoIpPort,

    /// Error returned by the URI parsing library.
    #[error("workload endpoint socket is not a valid URI")]
    Parse(#[from] ParseError),
}
