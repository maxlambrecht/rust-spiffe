//! Error types for the transport layer (gRPC/tonic).

use thiserror::Error;

/// A gRPC status code.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum GrpcStatusCode {
    /// The operation completed successfully.
    Ok,
    /// The operation was cancelled.
    Cancelled,
    /// An unknown error occurred.
    Unknown,
    /// The client supplied an invalid argument.
    InvalidArgument,
    /// The operation exceeded its deadline.
    DeadlineExceeded,
    /// The requested resource was not found.
    NotFound,
    /// The resource already exists.
    AlreadyExists,
    /// The caller does not have permission.
    PermissionDenied,
    /// A resource limit was exhausted.
    ResourceExhausted,
    /// A required precondition was not met.
    FailedPrecondition,
    /// The operation was aborted.
    Aborted,
    /// A value was outside the valid range.
    OutOfRange,
    /// The operation is not implemented.
    Unimplemented,
    /// An internal error occurred.
    Internal,
    /// The service is unavailable.
    Unavailable,
    /// Unrecoverable data loss or corruption occurred.
    DataLoss,
    /// The request is not authenticated.
    Unauthenticated,
}

impl GrpcStatusCode {
    #[cfg(any(feature = "workload-api-x509", feature = "workload-api-jwt"))]
    const fn from_tonic(code: tonic::Code) -> Self {
        match code {
            tonic::Code::Ok => Self::Ok,
            tonic::Code::Cancelled => Self::Cancelled,
            tonic::Code::Unknown => Self::Unknown,
            tonic::Code::InvalidArgument => Self::InvalidArgument,
            tonic::Code::DeadlineExceeded => Self::DeadlineExceeded,
            tonic::Code::NotFound => Self::NotFound,
            tonic::Code::AlreadyExists => Self::AlreadyExists,
            tonic::Code::PermissionDenied => Self::PermissionDenied,
            tonic::Code::ResourceExhausted => Self::ResourceExhausted,
            tonic::Code::FailedPrecondition => Self::FailedPrecondition,
            tonic::Code::Aborted => Self::Aborted,
            tonic::Code::OutOfRange => Self::OutOfRange,
            tonic::Code::Unimplemented => Self::Unimplemented,
            tonic::Code::Internal => Self::Internal,
            tonic::Code::Unavailable => Self::Unavailable,
            tonic::Code::DataLoss => Self::DataLoss,
            tonic::Code::Unauthenticated => Self::Unauthenticated,
        }
    }

    /// Returns the lowercase gRPC status name, such as `"permission_denied"`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Cancelled => "cancelled",
            Self::Unknown => "unknown",
            Self::InvalidArgument => "invalid_argument",
            Self::DeadlineExceeded => "deadline_exceeded",
            Self::NotFound => "not_found",
            Self::AlreadyExists => "already_exists",
            Self::PermissionDenied => "permission_denied",
            Self::ResourceExhausted => "resource_exhausted",
            Self::FailedPrecondition => "failed_precondition",
            Self::Aborted => "aborted",
            Self::OutOfRange => "out_of_range",
            Self::Unimplemented => "unimplemented",
            Self::Internal => "internal",
            Self::Unavailable => "unavailable",
            Self::DataLoss => "data_loss",
            Self::Unauthenticated => "unauthenticated",
        }
    }
}

impl std::fmt::Display for GrpcStatusCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A gRPC error status.
///
/// Use [`Self::code`] to classify the failure. The message and optional error
/// source provide diagnostic context. Their text and the concrete source type
/// are not stable API contracts.
#[derive(Debug)]
pub struct GrpcStatusError {
    code: GrpcStatusCode,
    message: Box<str>,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl GrpcStatusError {
    fn new(code: GrpcStatusCode, message: impl Into<Box<str>>) -> Self {
        Self {
            code,
            message: message.into(),
            source: None,
        }
    }

    fn with_source(
        code: GrpcStatusCode,
        message: impl Into<Box<str>>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }

    /// Returns the gRPC status code.
    pub const fn code(&self) -> GrpcStatusCode {
        self.code
    }

    /// Returns the diagnostic status message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for GrpcStatusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "gRPC status {}: {}", self.code, self.message)
    }
}

impl std::error::Error for GrpcStatusError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.source.as_deref() {
            Some(source) => Some(source),
            None => None,
        }
    }
}

/// An error returned while establishing a gRPC transport connection.
///
/// The underlying error is available through [`std::error::Error::source`]
/// for diagnostics. Its concrete type and formatted message may change
/// between releases.
#[derive(Debug)]
pub struct TransportConnectError {
    source: Box<dyn std::error::Error + Send + Sync>,
}

impl TransportConnectError {
    fn new(source: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self {
            source: Box::new(source),
        }
    }
}

impl std::fmt::Display for TransportConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "gRPC transport connection failed: {}", self.source)
    }
}

impl std::error::Error for TransportConnectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

/// Errors produced by the shared transport layer (tonic channel/connector).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TransportError {
    /// The endpoint transport is unsupported on the current platform.
    #[error("unsupported endpoint transport: {scheme}")]
    UnsupportedEndpointTransport {
        /// The unsupported transport scheme.
        scheme: &'static str,
    },

    /// gRPC status returned by the Workload API.
    #[error(transparent)]
    Status(#[from] GrpcStatusError),

    /// Transport error while connecting to the Workload API.
    #[error(transparent)]
    Connect(#[from] TransportConnectError),
}

impl TransportError {
    /// Creates a gRPC status error from a code and message, without a diagnostic source.
    pub fn status(code: GrpcStatusCode, message: impl Into<Box<str>>) -> Self {
        Self::Status(GrpcStatusError::new(code, message))
    }

    /// Creates a gRPC status error with a diagnostic source.
    ///
    /// The supplied code determines the classification, and the code and message
    /// determine the formatted error. The source provides diagnostic context
    /// without overriding either value. Its concrete type and diagnostic text
    /// are not stable API contracts.
    pub fn status_with_source(
        code: GrpcStatusCode,
        message: impl Into<Box<str>>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self::Status(GrpcStatusError::with_source(code, message, source))
    }

    /// Creates a connection error with the supplied diagnostic source.
    ///
    /// The source is available through [`std::error::Error::source`].
    pub fn connect(source: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::Connect(TransportConnectError::new(source))
    }

    #[cfg(any(feature = "workload-api-x509", feature = "workload-api-jwt"))]
    pub(crate) fn from_status(source: tonic::Status) -> Self {
        let code = GrpcStatusCode::from_tonic(source.code());
        let message = source.message().to_owned();
        Self::status_with_source(code, message, source)
    }

    pub(crate) fn from_transport(source: tonic::transport::Error) -> Self {
        Self::connect(source)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error as _;

    #[test]
    fn status_display_uses_owned_code_and_message() {
        let err = TransportError::status(GrpcStatusCode::Unavailable, "agent unavailable");

        assert_eq!(
            err.to_string(),
            "gRPC status unavailable: agent unavailable"
        );
        let TransportError::Status(status) = &err else {
            panic!("expected status error");
        };
        assert_eq!(status.code(), GrpcStatusCode::Unavailable);
        assert_eq!(status.message(), "agent unavailable");

        assert!(status.source().is_none());
    }

    #[test]
    fn status_with_source_preserves_authoritative_fields_and_diagnostics() {
        let err = TransportError::status_with_source(
            GrpcStatusCode::Unavailable,
            "agent unavailable",
            std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "socket refused"),
        );
        assert_eq!(
            err.to_string(),
            "gRPC status unavailable: agent unavailable"
        );
        assert_eq!(
            err.source().expect("diagnostic source").to_string(),
            "socket refused"
        );
        let TransportError::Status(status) = err else {
            panic!("expected status error");
        };
        assert_eq!(status.code(), GrpcStatusCode::Unavailable);
        assert_eq!(status.message(), "agent unavailable");
    }

    #[cfg(any(feature = "workload-api-x509", feature = "workload-api-jwt"))]
    #[test]
    fn internally_converted_status_retains_diagnostic_source() {
        let err = TransportError::from_status(tonic::Status::unavailable("agent unavailable"));
        let TransportError::Status(status) = &err else {
            panic!("expected status error");
        };

        let foreign = status.source().expect("foreign status source");
        assert!(foreign.to_string().contains("agent unavailable"));
    }

    #[test]
    fn connect_display_is_dependency_independent() {
        let failure = tonic::transport::Endpoint::from_shared("http://")
            .expect_err("invalid endpoint should fail");
        let expected = failure.to_string();
        let err = TransportError::from_transport(failure);

        assert_eq!(
            err.to_string(),
            format!("gRPC transport connection failed: {expected}")
        );
        let TransportError::Connect(wrapper) = &err else {
            panic!("expected connection error");
        };
        assert_eq!(
            wrapper.source().expect("foreign source").to_string(),
            expected
        );
    }
}
