use crate::workload_api::error::WorkloadApiError;
use crate::workload_api::supervisor_common::LastError;
use std::fmt;
use thiserror::Error;

/// Errors returned by `X509Source`.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum X509SourceError {
    /// Failed to retrieve or refresh X.509 material from the source.
    ///
    /// During the initial synchronization performed by [`X509Source::new`](crate::X509Source::new)/
    /// [`X509SourceBuilder::build`](crate::X509SourceBuilder::build), most underlying
    /// [`WorkloadApiError`]s (e.g. transient connectivity failures, `NoIdentityIssued`)
    /// are retried with backoff rather than surfaced immediately. Endpoint configuration,
    /// fixed or from `SPIFFE_ENDPOINT_SOCKET`, is validated before synchronization. gRPC `INVALID_ARGUMENT` fails initial sync
    /// immediately; an unsupported `FetchX509SVID` returns [`Self::UnsupportedRpc`].
    /// Steady-state reconnects continue retrying after successful initial sync.
    #[error("x509 source error: {0}")]
    Source(#[from] WorkloadApiError),

    /// The required `FetchX509SVID` RPC returned gRPC `UNIMPLEMENTED` during initial sync.
    ///
    /// Includes failures in response headers or trailers before the first accepted
    /// item. The original Workload API error, status code, and diagnostic cause are
    /// retained. Correct the server/profile configuration and build a new source.
    /// After successful initialization, this status continues to be retried.
    #[error("required Workload API RPC FetchX509SVID is unsupported during initial synchronization: {0}")]
    UnsupportedRpc(#[source] WorkloadApiError),

    /// No SVID could be selected from the received context.
    ///
    /// This can occur when:
    /// - The picker rejects all available SVIDs
    /// - No default SVID is available and no picker is configured
    /// - The selected SVID is expired or the local clock is unavailable
    ///
    /// Initial synchronization requires a usable identity. Later complete updates
    /// still replace trust bundles even when this error prevents identity acquisition.
    /// If expiry is unexpected, check the host's clock for skew.
    #[error("no suitable svid found")]
    NoSuitableSvid,

    /// The monitored material RPC denied permission. Recovery requires a valid complete response.
    #[error("material withdrawn: {0}")]
    Withdrawn(#[source] std::sync::Arc<WorkloadApiError>),

    /// The source was closed.
    #[error("source is closed")]
    Closed,

    /// Initial synchronization did not complete within the configured
    /// [`X509SourceBuilder::initial_sync_timeout`](crate::X509SourceBuilder::initial_sync_timeout).
    ///
    /// `last_error` is the most recent recoverable failure observed before the
    /// timeout was returned. It is `None` if no attempt had failed by then. The
    /// deadline is not a cutoff for this field: a task polled after the deadline
    /// advances the sync once more before returning the timeout, so the failure may
    /// have been observed after the deadline. [`std::error::Error::source`] returns
    /// the same error; downcast it as `Box<X509SourceError>`, or match the field directly.
    ///
    /// The last error is a retrospective diagnostic, not the definitive cause of the
    /// timeout: a later attempt may have been pending, for a different reason, when
    /// the timeout was returned. Terminal failures are never wrapped here; they are returned
    /// directly without waiting for the deadline.
    #[error("initial synchronization timed out{}", LastError::new(.last_error.as_deref()))]
    #[non_exhaustive]
    InitialSyncTimeout {
        /// The most recent recoverable failure, if any attempt failed before the timeout.
        #[source]
        last_error: Option<Box<Self>>,
    },

    /// The workload API stream ended.
    ///
    /// This error occurs when the gRPC stream from the Workload API terminates
    /// normally (returns `None`). This is distinct from `Source(WorkloadApiError)`,
    /// which represents actual errors during stream operations.
    ///
    /// **When this occurs:**
    /// - The stream reaches end-of-stream (normal termination)
    /// - The connection is closed by the server
    ///
    /// **Not to be confused with:**
    /// - `Source(WorkloadApiError::EmptyResponse)` - occurs when the API returns
    ///   empty data, not when the stream ends
    /// - `Source(WorkloadApiError::Transport(...))` - occurs for transport-level errors
    #[error("workload api stream ended")]
    StreamEnded,

    /// Resource limit exceeded.
    ///
    /// This error indicates that a received X.509 context exceeds one of the configured
    /// resource limits. The error includes the kind of limit, the configured limit, and
    /// the actual value that exceeded it.
    #[error("resource limit exceeded: {kind} (limit={limit}, actual={actual})")]
    ResourceLimitExceeded {
        /// The kind of limit that was exceeded.
        kind: LimitKind,
        /// The configured limit value.
        limit: usize,
        /// The actual value that exceeded the limit.
        actual: usize,
    },

    /// Shutdown timeout exceeded.
    ///
    /// This error occurs when `shutdown_with_timeout()` is called and the background
    /// tasks do not complete within the specified timeout.
    #[error("shutdown timeout exceeded")]
    ShutdownTimeout,
}

impl X509SourceError {
    pub(super) fn initial_rpc_error(error: WorkloadApiError) -> Self {
        if error.is_unimplemented() {
            Self::UnsupportedRpc(error)
        } else {
            Self::Source(error)
        }
    }
}

/// The kind of resource limit that was exceeded.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum LimitKind {
    /// Maximum number of SVIDs exceeded.
    MaxSvids,
    /// Maximum number of bundles exceeded.
    MaxBundles,
    /// Maximum bundle DER bytes exceeded.
    MaxBundleDerBytes,
}

impl LimitKind {
    /// Returns a stable string representation of the limit kind.
    ///
    /// This is useful for error messages, metrics labels, and logging.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MaxSvids => "max_svids",
            Self::MaxBundles => "max_bundles",
            Self::MaxBundleDerBytes => "max_bundle_der_bytes",
        }
    }
}

impl fmt::Display for LimitKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error kinds for structured metrics reporting.
///
/// Use these stable, low-cardinality labels when recording metrics.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum MetricsErrorKind {
    /// Failed to create a Workload API client.
    ClientCreation,
    /// Failed to connect to the Workload API stream.
    StreamConnect,
    /// Error occurred while reading from the stream.
    StreamError,
    /// The Workload API stream ended unexpectedly.
    StreamEnded,
    /// The Workload API reported that no identity is issued to this workload.
    ///
    /// Recorded instead of `StreamConnect` or `StreamError` when the material RPC
    /// fails with this status, during initial synchronization and steady state.
    NoIdentityIssued,
    /// Initial synchronization with the Workload API failed.
    InitialSyncFailed,
    /// No suitable SVID could be selected from the context.
    NoSuitableSvid,
    /// Resource limit exceeded: maximum SVID count.
    LimitMaxSvids,
    /// Resource limit exceeded: maximum bundle count.
    LimitMaxBundles,
    /// Resource limit exceeded: maximum bundle DER bytes.
    LimitMaxBundleDerBytes,
    /// An X.509 context update was rejected (validation failed).
    UpdateRejected,
    /// Failed to join supervisor task during shutdown.
    SupervisorJoinFailed,
}

impl MetricsErrorKind {
    /// Returns a string representation of the error kind.
    ///
    /// This is useful for metrics systems that require string labels.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClientCreation => "client_creation",
            Self::StreamConnect => "stream_connect",
            Self::StreamError => "stream_error",
            Self::StreamEnded => "stream_ended",
            Self::NoIdentityIssued => "no_identity_issued",
            Self::InitialSyncFailed => "initial_sync_failed",
            Self::NoSuitableSvid => "no_suitable_svid",
            Self::LimitMaxSvids => "limit_max_svids",
            Self::LimitMaxBundles => "limit_max_bundles",
            Self::LimitMaxBundleDerBytes => "limit_max_bundle_der_bytes",
            Self::UpdateRejected => "update_rejected",
            Self::SupervisorJoinFailed => "supervisor_join_failed",
        }
    }
}

impl fmt::Display for MetricsErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::MetricsErrorKind;

    #[test]
    fn no_identity_issued_metrics_label_is_stable() {
        assert_eq!(
            MetricsErrorKind::NoIdentityIssued.as_str(),
            "no_identity_issued"
        );
        assert_eq!(
            MetricsErrorKind::NoIdentityIssued.to_string(),
            "no_identity_issued"
        );
    }
}
