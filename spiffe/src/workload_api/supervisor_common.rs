//! Common supervisor utilities shared between X.509 and JWT source supervisors.
//!
//! This module contains reusable components for managing Workload API connections,
//! error tracking, and backoff policies.

#![allow(dead_code)] // Items are used by x509_source and jwt_source supervisor modules

use std::time::Duration;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;

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
    pub(crate) fn new(max_consecutive: u32) -> Self {
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

    pub(crate) fn reset(&mut self) {
        self.consecutive_same_error = 0;
        self.last_error_kind = None;
    }

    pub(crate) fn consecutive_count(&self) -> u32 {
        self.consecutive_same_error
    }

    pub(crate) fn last_error_kind(&self) -> Option<ErrorKey> {
        self.last_error_kind
    }
}

pub(crate) async fn sleep_or_cancel(token: &CancellationToken, dur: Duration) -> bool {
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
pub(crate) fn next_backoff(current: Duration, max: Duration) -> Duration {
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

/// Slower backoff policy for "no identity issued" condition.
///
/// This is an expected transient state (workload may not be registered yet),
/// so we use a gentler backoff: starts at 1s, exponential up to 10s, with jitter.
pub(crate) fn next_backoff_for_no_identity(current: Duration) -> Duration {
    const MIN_BACKOFF_MS: u64 = 1000; // 1 second
    const MAX_BACKOFF_MS: u64 = 10000; // 10 seconds

    let current_with_min = current.max(Duration::from_millis(MIN_BACKOFF_MS));
    next_backoff(current_with_min, Duration::from_millis(MAX_BACKOFF_MS))
}
