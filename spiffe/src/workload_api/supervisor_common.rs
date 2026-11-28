//! Common supervisor utilities shared between X.509 and JWT source supervisors.
//!
//! This module contains reusable components for managing Workload API connections,
//! error tracking, and backoff policies.

use futures::future::{Map, Shared};
use futures::FutureExt as _;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::time::Duration;
use tokio::task::{AbortHandle, JoinError, JoinHandle};
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;

/// Public-owner cleanup is independent of the supervisor's references to Inner.
#[derive(Debug)]
pub(crate) struct SourceOwner {
    cancel: CancellationToken,
    abort: OnceLock<AbortHandle>,
}

impl SourceOwner {
    pub(crate) const fn new(cancel: CancellationToken) -> Self {
        Self {
            cancel,
            abort: OnceLock::new(),
        }
    }

    /// Installed synchronously after spawn, before another build await or public return.
    pub(crate) fn install_abort(&self, abort: AbortHandle) {
        let installed = self.abort.set(abort);
        debug_assert!(installed.is_ok(), "source supervisor installed only once");
    }
}

impl Drop for SourceOwner {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(abort) = self.abort.get() {
            abort.abort();
        }
    }
}

/// Compact joined outcome; does not retain a supervisor panic payload or Inner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum JoinOutcome {
    Finished,
    Cancelled,
    Panicked,
}

fn join_outcome(result: Result<(), JoinError>) -> JoinOutcome {
    match result {
        Ok(()) => JoinOutcome::Finished,
        Err(error) if error.is_panic() => JoinOutcome::Panicked,
        Err(_) => JoinOutcome::Cancelled,
    }
}

type JoinCompletion = Shared<Map<JoinHandle<()>, fn(Result<(), JoinError>) -> JoinOutcome>>;

/// Durable ownership of the single source supervisor, independent of shutdown waiters.
#[derive(Debug)]
pub(crate) struct SupervisorTask {
    completion: JoinCompletion,
    abort: AbortHandle,
    failure_reported: AtomicBool,
}

impl SupervisorTask {
    pub(crate) fn new(handle: JoinHandle<()>) -> Self {
        let map_outcome: fn(Result<(), JoinError>) -> JoinOutcome = join_outcome;
        Self {
            abort: handle.abort_handle(),
            completion: handle.map(map_outcome).shared(),
            failure_reported: AtomicBool::new(false),
        }
    }

    pub(crate) fn abort_handle(&self) -> AbortHandle {
        self.abort.clone()
    }

    /// The boolean records only this caller's grace expiry. Even after abort,
    /// returning requires observation of the actual joined task completion.
    pub(crate) async fn join(&self, timeout: Option<Duration>) -> (JoinOutcome, bool) {
        if let Some(timeout) = timeout {
            // Tokio timeout polls completion before the deadline, including zero grace.
            if let Ok(outcome) = tokio::time::timeout(timeout, self.completion.clone()).await {
                return (outcome, false);
            }
            self.abort.abort();
            (self.completion.clone().await, true)
        } else {
            (self.completion.clone().await, false)
        }
    }

    /// Claim diagnostics only after Shared has persisted completion. No callback
    /// runs in its mapper or while a lifecycle lock is held.
    pub(crate) fn report_failure_once(&self, outcome: JoinOutcome) -> bool {
        outcome != JoinOutcome::Finished && !self.failure_reported.swap(true, Ordering::AcqRel)
    }
}

/// Supervisor policy: maximum number of consecutive identical errors before suppressing WARN logs.
///
/// Applies to:
/// - client creation failures
/// - stream connection failures
/// - update validation rejections
pub(crate) const MAX_CONSECUTIVE_SAME_ERROR: u32 = 3;

/// Stream connection phase for diagnostics (distinguishes initial sync from steady-state supervisor).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StreamPhase {
    /// Initial sync phase during source construction.
    InitialSync,
    /// Steady-state supervisor loop maintaining the stream.
    Supervisor,
}

/// Allocation-free key type for error tracking categories.
///
/// Used by `ErrorTracker` to group errors for log suppression without requiring
/// string literals or heap allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ErrorKey {
    /// Client creation failures.
    ClientCreation,
    /// Stream connection failures.
    StreamConnect,
    /// Update rejection failures.
    UpdateRejected,
    /// No identity issued (expected transient state).
    NoIdentityIssued,
}

/// Helper for tracking repeated errors to suppress log noise.
///
/// This tracks consecutive occurrences of the same error kind and suppresses
/// log warnings after the first N consecutive occurrences. For the first N
/// consecutive occurrences of each error kind, logs are emitted at WARN level.
/// After that, logs are downgraded to DEBUG level to reduce noise.
///
/// When a different error kind occurs or errors stop, the counter resets.
pub(crate) struct ErrorTracker {
    last_error_kind: Option<ErrorKey>,
    consecutive_same_error: u32,
    max_consecutive: u32,
}

impl ErrorTracker {
    pub(crate) const fn new(max_consecutive: u32) -> Self {
        Self {
            last_error_kind: None,
            consecutive_same_error: 0,
            max_consecutive,
        }
    }

    pub(crate) fn record_error(&mut self, error_kind: ErrorKey) -> bool {
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

    pub(crate) const fn reset(&mut self) {
        self.consecutive_same_error = 0;
        self.last_error_kind = None;
    }

    pub(crate) const fn consecutive_count(&self) -> u32 {
        self.consecutive_same_error
    }

    pub(crate) const fn last_error_kind(&self) -> Option<ErrorKey> {
        self.last_error_kind
    }
}

pub(crate) async fn sleep_or_cancel(token: &CancellationToken, dur: Duration) -> bool {
    tokio::select! {
        () = token.cancelled() => true,
        () = sleep(dur) => false,
    }
}

/// Bounds the whole initial synchronization future by the configured deadline.
///
/// Returns `None` on timeout. The future is dropped before this returns, and
/// `cancel` is cancelled. A `None` timeout waits without a deadline.
///
/// The deadline is not a cutoff for the future's progress: each wake-up polls the
/// future before the timer. If the task resumes after the deadline, that poll still
/// runs. Output that is ready in it is returned instead of a timeout, and state it
/// records before returning pending is visible to the caller.
pub(crate) async fn with_initial_deadline<F: Future>(
    initial_sync: F,
    cancel: &CancellationToken,
    timeout: Option<Duration>,
) -> Option<F::Output> {
    let Some(timeout) = timeout else {
        return Some(initial_sync.await);
    };

    match tokio::time::timeout(timeout, initial_sync).await {
        Ok(output) => Some(output),
        Err(_elapsed) => {
            cancel.cancel();
            None
        }
    }
}

/// Formats the optional cause of an initial synchronization timeout.
pub(crate) struct LastError<'a, E>(Option<&'a E>);

impl<'a, E> LastError<'a, E> {
    pub(crate) const fn new(last_error: Option<&'a E>) -> Self {
        Self(last_error)
    }
}

impl<E: std::fmt::Display> std::fmt::Display for LastError<'_, E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Some(error) => write!(f, "; last error: {error}"),
            None => f.write_str(" before the first attempt completed"),
        }
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
pub(crate) fn next_backoff(current: Duration, max: Duration) -> Duration {
    let cur = u64::try_from(current.as_millis()).unwrap_or(u64::MAX);
    let max = u64::try_from(max.as_millis()).unwrap_or(u64::MAX);

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

    // Subtract jitter range from base before adding random jitter, so the
    // result stays within [base - jitter, base] instead of being clamped to
    // exactly `max` when base == max.
    let jitter_base = base.saturating_sub(jitter);
    Duration::from_millis(jitter_base.saturating_add(add))
}

/// Slower backoff policy for "no identity issued" condition.
///
/// This is an expected transient state (workload may not be registered yet),
/// so we use a gentler backoff: starts at 1s, exponential up to the effective
/// maximum (the lesser of the user-configured `max` and the default 10s cap),
/// with jitter.
pub(crate) fn next_backoff_for_no_identity(current: Duration, max: Duration) -> Duration {
    const MIN_BACKOFF_MS: u64 = 1000; // 1 second
    const DEFAULT_MAX_BACKOFF_MS: u64 = 10000; // 10 seconds

    let max_ms = u64::try_from(max.as_millis()).unwrap_or(u64::MAX);
    let effective_max = max_ms.min(DEFAULT_MAX_BACKOFF_MS);

    let current_with_min = current.max(Duration::from_millis(MIN_BACKOFF_MS));
    next_backoff(current_with_min, Duration::from_millis(effective_max))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn initial_deadline_elapse_returns_none_drops_future_and_cancels_token() {
        let cancel = CancellationToken::new();
        let (drop_tx, dropped) = tokio::sync::oneshot::channel::<()>();
        let pending = async move {
            let _drop_tx = drop_tx;
            std::future::pending::<()>().await;
        };

        let outcome = with_initial_deadline(pending, &cancel, Some(Duration::from_secs(5))).await;

        assert!(outcome.is_none());
        assert!(cancel.is_cancelled());
        assert!(
            dropped.await.is_err(),
            "the timed-out future is dropped before the helper returns"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn initial_deadline_returns_output_completed_before_deadline() {
        let cancel = CancellationToken::new();

        let outcome =
            with_initial_deadline(async { "synced" }, &cancel, Some(Duration::from_secs(60))).await;

        assert_eq!(outcome, Some("synced"));
        assert!(!cancel.is_cancelled());
    }

    async fn is_pending_after_one_poll<F: Future>(mut future: std::pin::Pin<&mut F>) -> bool {
        std::future::poll_fn(|cx| std::task::Poll::Ready(future.as_mut().poll(cx).is_pending()))
            .await
    }

    /// A task that resumes after the deadline polls the future once more before the
    /// timer, so a failure recorded in that poll replaces the earlier one.
    #[tokio::test(start_paused = true)]
    async fn initial_deadline_late_poll_records_failure_before_timing_out() {
        let cancel = CancellationToken::new();
        let (fail, failure) = tokio::sync::oneshot::channel();
        let mut last_error = None;
        {
            let attempts = async {
                last_error = Some("before the deadline");
                last_error = Some(failure.await.unwrap());
                std::future::pending::<()>().await;
            };
            let mut bounded = std::pin::pin!(with_initial_deadline(
                attempts,
                &cancel,
                Some(Duration::from_secs(5))
            ));
            assert!(is_pending_after_one_poll(bounded.as_mut()).await);

            // The failure arrives, but the task is not polled until after the deadline.
            tokio::time::advance(Duration::from_secs(10)).await;
            fail.send("after the deadline").unwrap();

            assert_eq!(bounded.await, None);
        }
        assert_eq!(last_error, Some("after the deadline"));
        assert!(cancel.is_cancelled());
    }

    #[tokio::test(start_paused = true)]
    async fn initial_deadline_late_poll_with_ready_output_is_not_a_timeout() {
        let cancel = CancellationToken::new();
        let (complete, completion) = tokio::sync::oneshot::channel();
        let mut bounded = std::pin::pin!(with_initial_deadline(
            completion,
            &cancel,
            Some(Duration::from_secs(5))
        ));
        assert!(is_pending_after_one_poll(bounded.as_mut()).await);

        tokio::time::advance(Duration::from_secs(10)).await;
        complete.send("synced").unwrap();

        assert_eq!(bounded.await, Some(Ok("synced")));
        assert!(!cancel.is_cancelled());
    }

    #[tokio::test]
    async fn no_initial_deadline_passes_output_through() {
        let cancel = CancellationToken::new();

        let outcome = with_initial_deadline(async { "synced" }, &cancel, None).await;

        assert_eq!(outcome, Some("synced"));
        assert!(!cancel.is_cancelled());
    }

    #[test]
    fn last_error_formats_cause_or_absence() {
        assert_eq!(
            LastError::new(Some(&"no identity issued")).to_string(),
            "; last error: no identity issued"
        );
        assert_eq!(
            LastError::<&str>::new(None).to_string(),
            " before the first attempt completed"
        );
    }

    #[test]
    fn next_backoff_at_max_preserves_jitter() {
        let max = Duration::from_secs(30);
        let lo = max.saturating_sub(max / 10);

        // Run multiple times to exercise the random jitter path.
        for _ in 0..100 {
            let result = next_backoff(max, max);
            // Result should be in [max - 10%, max].
            assert!(
                result >= lo && result <= max,
                "expected backoff in [{lo:?}, {max:?}], got {result:?}"
            );
        }

        // Verify that not all values are identical (jitter is present).
        let mut results = std::collections::HashSet::new();
        for _ in 0..100 {
            results.insert(next_backoff(max, max).as_millis());
        }
        assert!(
            results.len() > 1,
            "expected jitter to produce varying results, got {results:?}"
        );
    }

    #[test]
    fn no_identity_backoff_starts_at_minimum_1s() {
        // Even with a very small current backoff, the minimum is clamped to 1s,
        // then doubled to 2s by next_backoff. With jitter (0-10%), the result
        // lands in [1.8s, 2.0s].
        let result =
            next_backoff_for_no_identity(Duration::from_millis(100), Duration::from_secs(30));
        assert!(
            result >= Duration::from_millis(1800),
            "expected >= 1800ms (2s - 10% jitter), got {}ms",
            result.as_millis()
        );
    }

    #[test]
    fn no_identity_backoff_respects_default_10s_cap() {
        // Even with a high user-configured max, the effective max is 10s.
        let result = next_backoff_for_no_identity(Duration::from_secs(8), Duration::from_secs(60));
        assert!(
            result <= Duration::from_secs(11),
            "expected <= 11s (10s + jitter), got {}ms",
            result.as_millis()
        );
    }

    #[test]
    fn no_identity_backoff_respects_user_max_below_default() {
        // If user-configured max is 3s (below the 10s default), that should be the cap.
        let result = next_backoff_for_no_identity(Duration::from_secs(2), Duration::from_secs(3));
        assert!(
            result <= Duration::from_millis(3300),
            "expected <= 3.3s (3s + jitter), got {}ms",
            result.as_millis()
        );
    }

    #[test]
    fn no_identity_backoff_grows_exponentially() {
        let first = next_backoff_for_no_identity(Duration::from_secs(1), Duration::from_secs(30));
        let second = next_backoff_for_no_identity(first, Duration::from_secs(30));

        // Second backoff should be larger than first (exponential growth)
        assert!(
            second > first,
            "expected growth: first={}ms, second={}ms",
            first.as_millis(),
            second.as_millis()
        );
    }
}
