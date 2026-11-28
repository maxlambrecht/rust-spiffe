//! Error types for Workload API operations.

use std::fmt;

use thiserror::Error;

use crate::transport::EndpointError;
use crate::SpiffeIdError;
#[cfg(feature = "jwt")]
use crate::{JwtBundleError, JwtSvidError};
#[cfg(feature = "x509")]
use crate::{X509BundleError, X509SvidError};

#[cfg(any(feature = "workload-api-x509", feature = "workload-api-jwt"))]
use crate::transport::GrpcStatusCode;
#[cfg(any(feature = "workload-api-x509", feature = "workload-api-jwt"))]
use crate::transport::TransportError;

/// Errors produced by Workload API operations.
#[derive(Error)]
#[non_exhaustive]
pub enum WorkloadApiError {
    /// `SPIFFE_ENDPOINT_SOCKET` is not set.
    #[error("missing SPIFFE endpoint socket path (SPIFFE_ENDPOINT_SOCKET)")]
    MissingEndpointSocket,

    /// `SPIFFE_ENDPOINT_SOCKET` is not a valid UTF-8 string.
    ///
    /// The field holds the raw value, which may contain credentials. `Display` and
    /// `Debug` omit it; take care when reading the field directly.
    #[error("SPIFFE endpoint socket path is not a valid UTF-8 string")]
    NotUnicodeEndpointSocket(std::ffi::OsString),

    /// The Workload API returned an empty response.
    ///
    /// This error can occur when:
    /// - The gRPC stream ends unexpectedly
    /// - A response carries no SVIDs or bundles for the request
    /// - A non-conforming Workload API implementation omits the requested material
    ///
    /// An unregistered workload, or one whose selectors match no registration entry,
    /// is reported by SPIRE as [`Self::NoIdentityIssued`], not as an empty response.
    #[error("empty Workload API response")]
    EmptyResponse,

    /// The Workload API response omitted a field required by the SPIFFE Workload API.
    ///
    /// This indicates malformed response material from a non-conforming Workload API
    /// implementation, not a transport failure.
    #[error("Workload API response is missing required field: {field}")]
    MissingRequiredField {
        /// The protocol field that was absent or empty.
        field: &'static str,
    },

    /// A present Workload API response field violates a structure or consistency requirement.
    ///
    /// Only the field path is reported; response values may contain credentials.
    #[error("Workload API response has invalid field: {field}")]
    InvalidResponseField {
        /// The malformed protocol field.
        field: &'static str,
    },

    /// Failed to parse the Workload API endpoint string.
    #[error("invalid workload api endpoint: {0}")]
    Endpoint(#[from] EndpointError),

    /// The Workload API denied issuing an identity for this workload (e.g. selectors do not match).
    ///
    /// This error occurs when the SPIRE agent cannot match the workload to any
    /// registration entry based on the workload's selectors. On Kubernetes, the entry
    /// may be created after the workload starts.
    ///
    /// It is mapped from a gRPC `PERMISSION_DENIED` status whose message contains
    /// "no identity issued". The SPIFFE Workload API specifies only `PERMISSION_DENIED`;
    /// the message is SPIRE-specific, and other implementations surface
    /// [`Self::PermissionDenied`] instead.
    ///
    /// `X509Source` and `JwtSource` retry this error during construction, so an
    /// unbounded `build()` keeps waiting; set `initial_sync_timeout` to bound it. After
    /// construction, receiving it on the monitored stream withdraws the affected
    /// material until a valid complete response reauthorizes it.
    #[error("no identity issued")]
    NoIdentityIssued,

    /// The Workload API denied the request for other permission reasons.
    #[error("permission denied: {0}")]
    PermissionDenied(String),

    /// No JWT-SVID found with the requested hint.
    #[error("no JWT-SVID found with hint: {0}")]
    HintNotFound(String),

    /// Errors returned by the underlying transport.
    #[cfg(any(feature = "workload-api-x509", feature = "workload-api-jwt"))]
    #[error(transparent)]
    Transport(#[from] TransportError),

    /// Failed to parse an X.509 SVID from the Workload API response.
    #[cfg(feature = "x509")]
    #[error("failed to parse X.509 SVID: {0}")]
    X509Svid(#[from] X509SvidError),

    /// Failed to parse a JWT-SVID from the Workload API response.
    #[cfg(feature = "jwt")]
    #[error("failed to parse JWT-SVID: {0}")]
    JwtSvid(#[from] JwtSvidError),

    /// Failed to parse an X.509 bundle from the Workload API response.
    #[cfg(feature = "x509")]
    #[error("failed to parse X.509 bundle: {0}")]
    X509Bundle(#[from] X509BundleError),

    /// Failed to parse a JWT bundle from the Workload API response.
    #[cfg(feature = "jwt")]
    #[error("failed to parse JWT bundle: {0}")]
    JwtBundle(#[from] JwtBundleError),

    /// Failed to parse a SPIFFE identifier from the Workload API response.
    #[error("failed to parse SPIFFE ID: {0}")]
    SpiffeId(#[from] SpiffeIdError),
}

// Written by hand so that `NotUnicodeEndpointSocket` can omit its value. Every
// other variant is formatted as `#[derive(Debug)]` would format it.
impl fmt::Debug for WorkloadApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingEndpointSocket => f.write_str("MissingEndpointSocket"),
            // The raw value bypasses the endpoint parser and may contain user info.
            Self::NotUnicodeEndpointSocket(_) => f
                .debug_tuple("NotUnicodeEndpointSocket")
                .field(&format_args!("<redacted>"))
                .finish(),
            Self::EmptyResponse => f.write_str("EmptyResponse"),
            Self::MissingRequiredField { field } => f
                .debug_struct("MissingRequiredField")
                .field("field", field)
                .finish(),
            Self::InvalidResponseField { field } => f
                .debug_struct("InvalidResponseField")
                .field("field", field)
                .finish(),
            Self::Endpoint(inner) => f.debug_tuple("Endpoint").field(inner).finish(),
            Self::NoIdentityIssued => f.write_str("NoIdentityIssued"),
            Self::PermissionDenied(inner) => {
                f.debug_tuple("PermissionDenied").field(inner).finish()
            }
            Self::HintNotFound(inner) => f.debug_tuple("HintNotFound").field(inner).finish(),
            #[cfg(any(feature = "workload-api-x509", feature = "workload-api-jwt"))]
            Self::Transport(inner) => f.debug_tuple("Transport").field(inner).finish(),
            #[cfg(feature = "x509")]
            Self::X509Svid(inner) => f.debug_tuple("X509Svid").field(inner).finish(),
            #[cfg(feature = "jwt")]
            Self::JwtSvid(inner) => f.debug_tuple("JwtSvid").field(inner).finish(),
            #[cfg(feature = "x509")]
            Self::X509Bundle(inner) => f.debug_tuple("X509Bundle").field(inner).finish(),
            #[cfg(feature = "jwt")]
            Self::JwtBundle(inner) => f.debug_tuple("JwtBundle").field(inner).finish(),
            Self::SpiffeId(inner) => f.debug_tuple("SpiffeId").field(inner).finish(),
        }
    }
}

#[cfg(any(feature = "workload-api-x509", feature = "workload-api-jwt"))]
impl WorkloadApiError {
    /// Returns `true` for a gRPC `INVALID_ARGUMENT` status.
    ///
    /// Backoff alone does not correct an invalid request. `X509Source` and
    /// `JwtSource` fail initial synchronization on this status from their client
    /// factory or material stream RPC. After readiness, their supervisors retry
    /// with backoff while preserving the current snapshot and its permission.
    #[must_use]
    pub fn is_invalid_argument(&self) -> bool {
        matches!(
            self,
            Self::Transport(TransportError::Status(status))
                if status.code() == GrpcStatusCode::InvalidArgument
        )
    }

    #[cfg(any(feature = "x509-source", feature = "jwt-source"))]
    pub(crate) fn is_unimplemented(&self) -> bool {
        matches!(
            self,
            Self::Transport(TransportError::Status(status))
                if status.code() == GrpcStatusCode::Unimplemented
        )
    }

    pub(crate) fn from_status(status: tonic::Status) -> Self {
        if status.code() == tonic::Code::PermissionDenied {
            let msg = status.message();

            // SPIFFE only specifies PermissionDenied for this condition; this string is
            // SPIRE-specific. Other conforming implementations may use different wording and
            // will fall through to PermissionDenied, preserving correctness with less specific
            // logs/backoff.
            if msg.contains("no identity issued") {
                return Self::NoIdentityIssued;
            }

            return Self::PermissionDenied(msg.to_owned());
        }

        Self::Transport(TransportError::from_status(status))
    }
}

#[cfg(test)]
#[cfg(any(feature = "workload-api-x509", feature = "workload-api-jwt"))]
mod tests {
    use super::*;

    #[test]
    fn is_invalid_argument_true_for_invalid_argument_status() {
        let err = WorkloadApiError::from_status(tonic::Status::invalid_argument("bad request"));
        assert!(err.is_invalid_argument());
    }

    #[test]
    fn is_invalid_argument_false_for_other_transport_statuses() {
        let err = WorkloadApiError::from_status(tonic::Status::unavailable("try again"));
        assert!(!err.is_invalid_argument());
    }

    #[test]
    fn permission_denied_preserves_the_status_message() {
        let err = WorkloadApiError::from_status(tonic::Status::permission_denied("nope"));

        assert!(!err.is_invalid_argument());
        assert!(matches!(err, WorkloadApiError::PermissionDenied(message) if message == "nope"));
    }

    #[test]
    fn no_identity_issued_stays_a_distinct_permission_failure() {
        let err = WorkloadApiError::from_status(tonic::Status::permission_denied(
            "no identity issued for this workload",
        ));

        assert!(matches!(err, WorkloadApiError::NoIdentityIssued));
    }

    #[test]
    fn is_invalid_argument_false_for_non_transport_variants() {
        assert!(!WorkloadApiError::NoIdentityIssued.is_invalid_argument());
        assert!(!WorkloadApiError::EmptyResponse.is_invalid_argument());
    }
}
