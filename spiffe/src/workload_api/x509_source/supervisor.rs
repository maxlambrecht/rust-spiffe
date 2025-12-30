use super::builder::{ReconnectConfig, ResourceLimits};
use super::errors::{MetricsErrorKind, X509SourceError};
use super::limits::validate_context;
use super::metrics::MetricsRecorder;
use super::source::{ClientFactory, SvidPicker};
use crate::prelude::{debug, info, warn};
use crate::workload_api::client::WorkloadApiClient;
use crate::workload_api::error::WorkloadApiError;
use crate::workload_api::x509_context::X509Context;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tokio_stream::StreamExt;
use tokio_util::sync::CancellationToken;

/// Allocation-free key type for error tracking categories.
///
/// Used by `ErrorTracker` to group errors for log suppression without requiring
/// string literals or heap allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum ErrorKey {
    /// Client creation failures.
    ClientCreation,
    /// Stream connection failures.
    StreamConnect,
    /// Update rejection failures.
    UpdateRejected,
}

/// Helper for tracking repeated errors to suppress log noise.
///
/// This tracks consecutive occurrences of the same error kind and suppresses
/// log warnings after the first N consecutive occurrences. For the first N
/// consecutive occurrences of each error kind, logs are emitted at WARN level.
/// After that, logs are downgraded to DEBUG level to reduce noise.
///
/// When a different error kind occurs or errors stop, the counter resets.
pub(super) struct ErrorTracker {
    last_error_kind: Option<ErrorKey>,
    consecutive_same_error: u32,
    max_consecutive: u32,
}

impl ErrorTracker {
    pub(super) fn new(max_consecutive: u32) -> Self {
        Self {
            last_error_kind: None,
            consecutive_same_error: 0,
            max_consecutive,
        }
    }

    pub(super) fn record_error(&mut self, error_kind: ErrorKey) -> bool {
        let should_warn = self.last_error_kind != Some(error_kind)
            || self.consecutive_same_error < self.max_consecutive;

        if self.last_error_kind == Some(error_kind) {
            self.consecutive_same_error += 1;
        } else {
            self.consecutive_same_error = 1;
            self.last_error_kind = Some(error_kind);
        }

        should_warn
    }

    pub(super) fn reset(&mut self) {
        self.consecutive_same_error = 0;
        self.last_error_kind = None;
    }

    pub(super) fn consecutive_count(&self) -> u32 {
        self.consecutive_same_error
    }
}

/// Attempts to create a Workload API client.
///
/// Records metrics and logs errors. Resets backoff to `min_backoff` on success.
/// Does not sleep; the caller is responsible for backoff progression and sleeping.
///
/// On error, records `ClientCreation` metric. The caller should call `record_reconnect`
/// for steady-state reconnections (not for initial sync).
pub(super) async fn try_create_client(
    make_client: &ClientFactory,
    source_id: u64,
    min_backoff: Duration,
    backoff: &mut Duration,
    error_tracker: &mut ErrorTracker,
    metrics: Option<&dyn MetricsRecorder>,
) -> Result<WorkloadApiClient, WorkloadApiError> {
    match (make_client)().await {
        Ok(c) => {
            if error_tracker.consecutive_count() > 0 {
                debug!(
                    "Client creation recovered after {} consecutive failures: source_id={}",
                    error_tracker.consecutive_count(),
                    source_id
                );
            }
            error_tracker.reset();
            *backoff = min_backoff;
            Ok(c)
        }
        Err(e) => {
            let error_kind = ErrorKey::ClientCreation;
            let should_warn = error_tracker.record_error(error_kind);

            if should_warn {
                warn!(
                    "Failed to create WorkloadApiClient; retrying: source_id={}, error={}, backoff_ms={}",
                    source_id,
                    e,
                    backoff.as_millis()
                );
            } else {
                debug!(
                    "Failed to create WorkloadApiClient (repeated); retrying: source_id={}, error={}, backoff_ms={}, consecutive_failures={}",
                    source_id,
                    e,
                    backoff.as_millis(),
                    error_tracker.consecutive_count()
                );
            }

            if let Some(m) = metrics {
                m.record_error(MetricsErrorKind::ClientCreation);
            }
            Err(e)
        }
    }
}

/// Attempts to connect to the X.509 context stream.
///
/// Records metrics and logs errors. Resets backoff to `min_backoff` on success.
/// Does not sleep; the caller is responsible for backoff progression and sleeping.
///
/// On error, records `StreamConnect` metric. The caller should call `record_reconnect`
/// for steady-state reconnections (not for initial sync).
pub(super) async fn try_connect_stream(
    client: &WorkloadApiClient,
    source_id: u64,
    min_backoff: Duration,
    backoff: &mut Duration,
    error_tracker: &mut ErrorTracker,
    metrics: Option<&dyn MetricsRecorder>,
) -> Result<
    impl tokio_stream::Stream<Item = Result<X509Context, WorkloadApiError>> + Send + 'static,
    WorkloadApiError,
> {
    match client.stream_x509_contexts().await {
        Ok(s) => {
            if error_tracker.consecutive_count() > 0 {
                info!(
                    "Stream connection recovered after {} consecutive failures: source_id={}",
                    error_tracker.consecutive_count(),
                    source_id
                );
            }
            error_tracker.reset();
            info!(
                "Connected to Workload API X509 context stream: source_id={}",
                source_id
            );
            *backoff = min_backoff;
            Ok(s)
        }
        Err(e) => {
            let error_kind = ErrorKey::StreamConnect;
            let should_warn = error_tracker.record_error(error_kind);

            if should_warn {
                warn!(
                    "Failed to connect to Workload API stream; retrying: source_id={}, error={}, backoff_ms={}",
                    source_id,
                    e,
                    backoff.as_millis()
                );
            } else {
                debug!(
                    "Failed to connect to Workload API stream (repeated); retrying: source_id={}, error={}, backoff_ms={}, consecutive_failures={}",
                    source_id,
                    e,
                    backoff.as_millis(),
                    error_tracker.consecutive_count()
                );
            }

            if let Some(m) = metrics {
                m.record_error(MetricsErrorKind::StreamConnect);
            }
            Err(e)
        }
    }
}

pub(super) async fn initial_sync_with_retry(
    make_client: &ClientFactory,
    picker: Option<&dyn SvidPicker>,
    cancel: &CancellationToken,
    reconnect: ReconnectConfig,
    limits: ResourceLimits,
    metrics: Option<&dyn MetricsRecorder>,
    source_id: u64,
) -> Result<Arc<X509Context>, X509SourceError> {
    let mut backoff = reconnect.min_backoff;
    let mut error_tracker = ErrorTracker::new(3);

    loop {
        if cancel.is_cancelled() {
            return Err(X509SourceError::Closed);
        }

        match try_sync_once(
            make_client,
            picker,
            limits,
            metrics,
            source_id,
            reconnect.min_backoff,
            &mut backoff,
            &mut error_tracker,
        )
        .await
        {
            Ok(v) => return Ok(v),
            Err(_e) => {
                // Record InitialSyncFailed as an umbrella metric for any failed attempt.
                // Specific metrics (ClientCreation, StreamConnect, StreamError, StreamEnded,
                // LimitMaxSvids, LimitMaxBundles, LimitMaxBundleDerBytes, NoSuitableSvid)
                // are already recorded in try_sync_once(). Detailed logs are also produced
                // by try_create_client/try_connect_stream/stream read, so we avoid duplicate
                // outer logs here to reduce noise.
                if let Some(m) = metrics {
                    m.record_error(MetricsErrorKind::InitialSyncFailed);
                }
                if sleep_or_cancel(cancel, backoff).await {
                    return Err(X509SourceError::Closed);
                }
                backoff = next_backoff(backoff, reconnect.max_backoff);
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn try_sync_once(
    make_client: &ClientFactory,
    picker: Option<&dyn SvidPicker>,
    limits: ResourceLimits,
    metrics: Option<&dyn MetricsRecorder>,
    source_id: u64,
    min_backoff: Duration,
    backoff: &mut Duration,
    error_tracker: &mut ErrorTracker,
) -> Result<Arc<X509Context>, X509SourceError> {
    // Use shared client creation logic (records ClientCreation metric on failure).
    // Initial sync does not record reconnect metrics (it's not a reconnect).
    let client = match try_create_client(
        make_client,
        source_id,
        min_backoff,
        backoff,
        error_tracker,
        metrics,
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            // Error already logged and metric recorded by try_create_client.
            return Err(X509SourceError::Source(e));
        }
    };

    // Use shared stream connection logic (records StreamConnect metric on failure).
    let mut stream = match try_connect_stream(
        &client,
        source_id,
        min_backoff,
        backoff,
        error_tracker,
        metrics,
    )
    .await
    {
        Ok(s) => s,
        Err(e) => {
            // Error already logged and metric recorded by try_connect_stream.
            return Err(X509SourceError::Source(e));
        }
    };

    match stream.next().await {
        Some(Ok(ctx)) => {
            validate_context(&ctx, picker, limits, metrics)?;

            Ok(Arc::new(ctx))
        }
        Some(Err(e)) => {
            // Record StreamError for stream read errors.
            if let Some(m) = metrics {
                m.record_error(MetricsErrorKind::StreamError);
            }
            Err(X509SourceError::Source(e))
        }
        None => {
            // Record StreamEnded for empty stream.
            if let Some(m) = metrics {
                m.record_error(MetricsErrorKind::StreamEnded);
            }
            Err(X509SourceError::StreamEnded)
        }
    }
}

pub(super) async fn sleep_or_cancel(token: &CancellationToken, dur: Duration) -> bool {
    tokio::select! {
        () = token.cancelled() => true,
        () = sleep(dur) => false,
    }
}

/// Exponential backoff with small jitter.
///
/// Computes the next backoff duration by:
/// 1. Doubling the current duration (exponential growth)
/// 2. Clamping to the maximum duration
/// 3. Adding small jitter (0-10% of the base) to prevent synchronized reconnect storms
///
/// The jitter is especially important in container fleets that start simultaneously.
///
/// Note: Jitter is calculated in milliseconds, which may result in sub-millisecond
/// precision loss for very small durations. This is acceptable for backoff purposes.
#[allow(clippy::cast_possible_truncation)]
pub(super) fn next_backoff(current: Duration, max: Duration) -> Duration {
    let doubled = current.saturating_mul(2);
    let base = doubled.min(max);

    let base_ms = base.as_millis();
    if base_ms == 0 {
        return base;
    }

    // Add jitter: 0-10% of base
    let jitter_max_ms = (base_ms / 10).min(u128::from(u64::MAX)) as u64;
    let jitter_ms = if jitter_max_ms > 0 {
        fastrand::u64(0..=jitter_max_ms)
    } else {
        0
    };

    // Result = base + jitter, clamped to max
    let total_ms = base_ms.saturating_add(u128::from(jitter_ms));
    let total_ms_clamped = total_ms.min(max.as_millis()).min(u128::from(u64::MAX)) as u64;
    Duration::from_millis(total_ms_clamped)
}
