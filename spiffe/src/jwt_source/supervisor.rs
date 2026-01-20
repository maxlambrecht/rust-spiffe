use super::builder::{ReconnectConfig, ResourceLimits};
use super::errors::{JwtSourceError, MetricsErrorKind};
use super::limits::validate_bundle_set;
use super::metrics::MetricsRecorder;
use super::source::Inner;
use super::types::ClientFactory;
use crate::bundle::jwt::JwtBundleSet;
use crate::prelude::{debug, info, warn};
use crate::workload_api::error::WorkloadApiError;
use crate::workload_api::WorkloadApiClient;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tokio_stream::StreamExt;
use tokio_util::sync::CancellationToken;

/// Supervisor policy: maximum number of consecutive identical errors before suppressing WARN logs.
///
/// Applies to:
/// - client creation failures
/// - stream connection failures
/// - update validation rejections
const MAX_CONSECUTIVE_SAME_ERROR: u32 = 3;

/// Stream connection phase for diagnostics (distinguishes initial sync from steady-state supervisor).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StreamPhase {
    /// Initial sync phase during `JwtSource` construction.
    InitialSync,
    /// Steady-state supervisor loop maintaining the stream.
    Supervisor,
}

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
    min_backoff: Duration,
    backoff: &mut Duration,
    error_tracker: &mut ErrorTracker,
    metrics: Option<&dyn MetricsRecorder>,
) -> Result<WorkloadApiClient, WorkloadApiError> {
    match (make_client)().await {
        Ok(c) => {
            if error_tracker.consecutive_count() > 0 {
                debug!(
                    "Client creation recovered after {} consecutive failures",
                    error_tracker.consecutive_count()
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
                    "Failed to create WorkloadApiClient; retrying: error={}, backoff_ms={}",
                    e,
                    backoff.as_millis()
                );
            } else {
                debug!(
                    "Failed to create WorkloadApiClient (repeated); retrying: error={}, backoff_ms={}, consecutive_failures={}",
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

/// Attempts to connect to the JWT bundle stream.
///
/// Records metrics and logs errors. Resets backoff to `min_backoff` on success.
/// Does not sleep; the caller is responsible for backoff progression and sleeping.
///
/// On error, records `StreamConnect` metric. The caller should call `record_reconnect`
/// for steady-state reconnections (not for initial sync).
pub(super) async fn try_connect_stream(
    client: &WorkloadApiClient,
    min_backoff: Duration,
    backoff: &mut Duration,
    error_tracker: &mut ErrorTracker,
    metrics: Option<&dyn MetricsRecorder>,
    _phase: StreamPhase,
    supervisor_id: Option<u64>,
) -> Result<
    impl tokio_stream::Stream<Item = Result<JwtBundleSet, WorkloadApiError>> + Send + 'static,
    WorkloadApiError,
> {
    match client.stream_jwt_bundles().await {
        Ok(s) => {
            let _id_suffix = supervisor_id.map_or_else(String::new, |id| format!(", id={id}"));

            if error_tracker.consecutive_count() > 0 {
                info!(
                    "Stream connection recovered after {} consecutive failures (phase={:?}{})",
                    error_tracker.consecutive_count(),
                    _phase,
                    _id_suffix
                );
            }
            error_tracker.reset();
            info!(
                "Connected to Workload API JWT bundle stream (phase={:?}{})",
                _phase, _id_suffix
            );
            *backoff = min_backoff;
            Ok(s)
        }
        Err(e) => {
            let error_kind = ErrorKey::StreamConnect;
            let should_warn = error_tracker.record_error(error_kind);

            if should_warn {
                warn!(
                    "Failed to connect to Workload API stream; retrying: error={}, backoff_ms={}",
                    e,
                    backoff.as_millis()
                );
            } else {
                debug!(
                    "Failed to connect to Workload API stream (repeated); retrying: error={}, backoff_ms={}, consecutive_failures={}",
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
    cancel: &CancellationToken,
    reconnect: ReconnectConfig,
    limits: ResourceLimits,
    metrics: Option<&dyn MetricsRecorder>,
) -> Result<Arc<JwtBundleSet>, JwtSourceError> {
    let mut backoff = reconnect.min_backoff;
    let mut error_tracker = ErrorTracker::new(3);

    loop {
        if cancel.is_cancelled() {
            return Err(JwtSourceError::Closed);
        }

        match try_sync_once(
            make_client,
            limits,
            metrics,
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
                // LimitMaxBundles, LimitMaxBundleJwksBytes) are already recorded in try_sync_once().
                // Detailed logs are also produced by try_create_client/try_connect_stream/stream read,
                // so we avoid duplicate outer logs here to reduce noise.
                if let Some(m) = metrics {
                    m.record_error(MetricsErrorKind::InitialSyncFailed);
                }
                if sleep_or_cancel(cancel, backoff).await {
                    return Err(JwtSourceError::Closed);
                }
                backoff = next_backoff(backoff, reconnect.max_backoff);
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn try_sync_once(
    make_client: &ClientFactory,
    limits: ResourceLimits,
    metrics: Option<&dyn MetricsRecorder>,
    min_backoff: Duration,
    backoff: &mut Duration,
    error_tracker: &mut ErrorTracker,
) -> Result<Arc<JwtBundleSet>, JwtSourceError> {
    // Use shared client creation logic (records ClientCreation metric on failure).
    // Initial sync does not record reconnect metrics (it's not a reconnect).
    let client =
        match try_create_client(make_client, min_backoff, backoff, error_tracker, metrics).await {
            Ok(c) => c,
            Err(e) => {
                return Err(JwtSourceError::Source(e));
            }
        };

    // Use shared stream connection logic (records StreamConnect metric on failure).
    let mut stream = match try_connect_stream(
        &client,
        min_backoff,
        backoff,
        error_tracker,
        metrics,
        StreamPhase::InitialSync,
        None,
    )
    .await
    {
        Ok(s) => s,
        Err(e) => {
            return Err(JwtSourceError::Source(e));
        }
    };

    match stream.next().await {
        Some(Ok(bundle_set)) => {
            validate_bundle_set(&bundle_set, limits, metrics).inspect_err(|_e| {
                warn!("Initial JWT bundle set rejected; will retry: error={}", _e);
            })?;

            Ok(Arc::new(bundle_set))
        }
        Some(Err(e)) => {
            // Record StreamError for stream read errors.
            warn!(
                "Initial sync: Workload API stream error; will retry: error={}",
                e
            );
            if let Some(m) = metrics {
                m.record_error(MetricsErrorKind::StreamError);
            }
            Err(JwtSourceError::Source(e))
        }
        None => {
            // Record StreamEnded for empty stream.
            warn!("Initial sync: Workload API stream ended immediately; will retry");
            if let Some(m) = metrics {
                m.record_error(MetricsErrorKind::StreamEnded);
            }
            Err(JwtSourceError::StreamEnded)
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
    let cur = current.as_millis().min(u128::from(u64::MAX)) as u64;
    let max = max.as_millis().min(u128::from(u64::MAX)) as u64;

    let base = (cur.saturating_mul(2)).min(max);
    if base == 0 {
        return Duration::from_millis(0);
    }

    let jitter = base / 10;
    let add = if jitter > 0 {
        fastrand::u64(0..=jitter)
    } else {
        0
    };

    Duration::from_millis((base.saturating_add(add)).min(max))
}

impl Inner {
    pub(super) async fn run_update_supervisor(&self, cancellation_token: CancellationToken) {
        // Generate a unique supervisor ID for diagnostics (detects duplicate supervisors/repeated constructions).
        let supervisor_id = fastrand::u64(..);
        info!("Starting update supervisor: id={}", supervisor_id);

        let mut backoff = self.reconnect().min_backoff;
        let mut error_tracker = ErrorTracker::new(MAX_CONSECUTIVE_SAME_ERROR);

        loop {
            if cancellation_token.is_cancelled() {
                debug!("Cancellation signal received; stopping updates");
                return;
            }

            let Ok(client) = try_create_client(
                self.make_client(),
                self.reconnect().min_backoff,
                &mut backoff,
                &mut error_tracker,
                self.metrics(),
            )
            .await
            else {
                if self
                    .backoff_and_maybe_cancel(&cancellation_token, backoff)
                    .await
                {
                    return;
                }
                backoff = next_backoff(backoff, self.reconnect().max_backoff);
                continue;
            };

            let Ok(mut stream) = try_connect_stream(
                &client,
                self.reconnect().min_backoff,
                &mut backoff,
                &mut error_tracker,
                self.metrics(),
                StreamPhase::Supervisor,
                Some(supervisor_id),
            )
            .await
            else {
                if self
                    .backoff_and_maybe_cancel(&cancellation_token, backoff)
                    .await
                {
                    return;
                }
                backoff = next_backoff(backoff, self.reconnect().max_backoff);
                continue;
            };

            // Process stream updates. Returns true if cancelled, false if reconnect needed.
            let cancelled = self
                .process_stream_updates(&mut stream, &cancellation_token, supervisor_id)
                .await;
            if cancelled {
                return;
            }

            // Stream ended or errored. Sleep/backoff before retrying.
            if self
                .backoff_and_maybe_cancel(&cancellation_token, backoff)
                .await
            {
                return;
            }
            backoff = next_backoff(backoff, self.reconnect().max_backoff);
        }
    }

    async fn backoff_and_maybe_cancel(&self, token: &CancellationToken, backoff: Duration) -> bool {
        if let Some(metrics) = self.metrics() {
            metrics.record_reconnect();
        }
        sleep_or_cancel(token, backoff).await
    }

    async fn process_stream_updates(
        &self,
        stream: &mut (impl tokio_stream::Stream<Item = Result<JwtBundleSet, WorkloadApiError>>
                  + Unpin
                  + Send
                  + 'static),
        cancellation_token: &CancellationToken,
        _supervisor_id: u64,
    ) -> bool {
        let mut update_rejection_tracker = ErrorTracker::new(MAX_CONSECUTIVE_SAME_ERROR);

        loop {
            let item = tokio::select! {
                () = cancellation_token.cancelled() => {
                    debug!("Cancellation signal received; stopping update loop");
                    return true;
                }
                v = stream.next() => v,
            };

            match item {
                Some(Ok(bundle_set)) => {
                    match self.apply_update(std::sync::Arc::new(bundle_set)) {
                        Ok(()) => {
                            if update_rejection_tracker.consecutive_count() > 0 {
                                info!(
                                    "Update validation recovered after {} consecutive failures",
                                    update_rejection_tracker.consecutive_count(),
                                );
                                update_rejection_tracker.reset();
                            }
                            info!("JWT bundle set updated");
                        }
                        Err(_e) => {
                            let should_warn =
                                update_rejection_tracker.record_error(ErrorKey::UpdateRejected);

                            if should_warn {
                                warn!("Rejected JWT bundle set update: error={}", _e);
                            } else {
                                debug!(
                                    "Rejected JWT bundle set update (repeated): error={}, consecutive_rejections={}",
                                    _e,
                                    update_rejection_tracker.consecutive_count()
                                );
                            }
                            // Metrics already recorded by apply_update(); do not double-count.
                        }
                    }
                }
                Some(Err(_e)) => {
                    warn!(
                        "Workload API stream error; reconnecting: id={}, error={}",
                        _supervisor_id, _e
                    );
                    self.record_error(MetricsErrorKind::StreamError);
                    return false;
                }
                None => {
                    warn!(
                        "Workload API stream ended; reconnecting: id={}",
                        _supervisor_id
                    );
                    self.record_error(MetricsErrorKind::StreamEnded);
                    return false;
                }
            }
        }
    }
}
