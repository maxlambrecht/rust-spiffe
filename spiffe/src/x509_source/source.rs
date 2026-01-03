use super::builder::{ReconnectConfig, ResourceLimits};
use super::errors::{MetricsErrorKind, X509SourceError};
use super::limits::{select_svid, validate_context};
use super::metrics::MetricsRecorder;
use super::supervisor::initial_sync_with_retry;
use crate::bundle::BundleSource;
use crate::prelude::warn;
use crate::svid::SvidSource;
use crate::workload_api::x509_context::X509Context;
use crate::x509_source::types::{ClientFactory, SvidPicker};
use crate::{TrustDomain, X509Bundle, X509BundleSet, X509SourceBuilder, X509Svid};
use arc_swap::ArcSwap;
use std::fmt::Debug;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{watch, Mutex};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

#[cfg(test)]
use crate::WorkloadApiError;

/// Handle for receiving update notifications from an [`X509Source`].
///
/// This type wraps the underlying notification mechanism and provides a clean
/// API for detecting when the X.509 context has been updated.
///
/// Cloning this handle creates another receiver that shares the same update
/// stream. Each receiver observes the latest sequence number; if a receiver
/// is slow to consume updates, intermediate sequence numbers may be skipped
/// (this is the standard behavior of `watch` channels).
///
/// # Examples
///
/// ```no_run
/// # use spiffe::X509Source;
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let source = X509Source::new().await?;
/// let mut updates = source.updated();
///
/// // Wait for an update
/// updates.changed().await?;
/// println!("Update sequence: {}", updates.last());
///
/// // Wait for another update
/// updates.changed().await?;
/// println!("New sequence: {}", updates.last());
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct X509SourceUpdates {
    rx: watch::Receiver<u64>,
}

impl X509SourceUpdates {
    /// Waits for the next update and returns the new sequence number.
    ///
    /// This method waits for the next rotation after initial synchronization.
    /// The initial sync does not trigger a notification; only subsequent updates
    /// are notified.
    ///
    /// This method will return an error if the source has been closed or
    /// the internal update task has terminated (e.g., due to shutdown or
    /// an internal error).
    ///
    /// # Errors
    ///
    /// Returns [`X509SourceError::Closed`] if the source has been shut down
    /// or the internal update task has terminated. This can occur due to:
    /// - Explicit shutdown via [`X509Source::shutdown`] or [`X509Source::shutdown_with_timeout`]
    /// - Internal task termination (e.g., supervisor task panic)
    pub async fn changed(&mut self) -> Result<u64, X509SourceError> {
        self.rx
            .changed()
            .await
            .map_err(|_| X509SourceError::Closed)?;
        Ok(*self.rx.borrow())
    }

    /// Returns the last sequence number without waiting.
    ///
    /// This method never blocks and always returns immediately with the
    /// current sequence number.
    pub fn last(&self) -> u64 {
        *self.rx.borrow()
    }

    /// Waits for the sequence number to satisfy a predicate.
    ///
    /// This method first checks the current sequence number; if the predicate
    /// is already satisfied, it returns immediately without waiting. Otherwise,
    /// it repeatedly calls `changed()` until the predicate returns `true`.
    ///
    /// # Errors
    ///
    /// Returns an error if the source has been closed.
    pub async fn wait_for<F>(&mut self, mut f: F) -> Result<u64, X509SourceError>
    where
        F: FnMut(&u64) -> bool,
    {
        let current = self.last();
        if f(&current) {
            return Ok(current);
        }
        loop {
            let seq = self.changed().await?;
            if f(&seq) {
                return Ok(seq);
            }
        }
    }
}

/// Live source of X.509 SVIDs and bundles from the SPIFFE Workload API.
///
/// `X509Source` performs an initial sync before returning from [`X509Source::new`] or
/// [`X509SourceBuilder::build`]. Updates are applied atomically and can be observed via
/// [`X509Source::updated`].
///
/// The source automatically:
/// - Maintains a cached view of the latest X.509 materials
/// - Handles SVID and bundle rotation transparently
/// - Reconnects with exponential backoff on transient failures
/// - Validates resource limits before publishing updates
///
/// Use [`X509Source::shutdown`] or [`X509Source::shutdown_configured`] to stop background tasks.
///
#[derive(Clone, Debug)]
pub struct X509Source {
    inner: Arc<Inner>,
}

pub(super) struct Inner {
    // Atomically replaced, last-known-good X.509 context (SVIDs + bundles).
    x509_context: ArcSwap<X509Context>,

    // Policy for selecting an SVID when multiple are present.
    svid_picker: Option<Box<dyn SvidPicker>>,
    limits: ResourceLimits,

    // Supervisor configuration and dependencies.
    reconnect: ReconnectConfig,
    make_client: ClientFactory,
    metrics: Option<Arc<dyn MetricsRecorder>>,

    // Lifecycle / shutdown.
    closed: AtomicBool,
    cancel: CancellationToken,
    shutdown_timeout: Option<Duration>,

    // Update notifications (monotonic sequence).
    update_seq: AtomicU64,
    update_tx: watch::Sender<u64>,
    update_rx: watch::Receiver<u64>,

    // Supervisor task handle (joined/aborted at shutdown).
    supervisor: Mutex<Option<JoinHandle<()>>>,
}

impl Inner {
    pub(super) fn reconnect(&self) -> ReconnectConfig {
        self.reconnect
    }
    pub(super) fn metrics(&self) -> Option<&dyn MetricsRecorder> {
        self.metrics.as_deref()
    }
    pub(super) fn make_client(&self) -> &ClientFactory {
        &self.make_client
    }
}

impl Debug for Inner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X509Source")
            .field("x509_context", &"<ArcSwap<X509Context>>")
            .field(
                "svid_picker",
                &self.svid_picker.as_ref().map(|_| "<SvidPicker>"),
            )
            .field("reconnect", &self.reconnect)
            .field("limits", &self.limits)
            .field("make_client", &"<ClientFactory>")
            .field(
                "metrics",
                &self.metrics.as_ref().map(|_| "<MetricsRecorder>"),
            )
            .field("shutdown_timeout", &self.shutdown_timeout)
            .field("closed", &self.closed.load(Ordering::Relaxed))
            .field("cancel", &self.cancel)
            .field("update_seq", &self.update_seq)
            .field("update_tx", &"<watch::Sender<u64>>")
            .field("update_rx", &"<watch::Receiver<u64>>")
            .field("supervisor", &"<Mutex<Option<JoinHandle<()>>>>")
            .finish()
    }
}

impl X509Source {
    /// Creates an `X509Source` using the default Workload API endpoint.
    ///
    /// The endpoint is resolved from `SPIFFE_ENDPOINT_SOCKET`. The source selects the default
    /// X.509 SVID when multiple SVIDs are available.
    ///
    /// On success, the returned source is already synchronized with the agent and will keep
    /// updating in the background until it is closed.
    ///
    /// # Errors
    ///
    /// Returns an [`X509SourceError`] if:
    /// - the Workload API endpoint cannot be resolved or connected to,
    /// - the initial synchronization with the Workload API does not complete successfully,
    /// - or no suitable X.509 SVID can be selected from the received context.
    pub async fn new() -> Result<Self, X509SourceError> {
        X509SourceBuilder::new().build().await
    }

    /// Creates a builder for configuring an [`X509Source`].
    ///
    /// The builder allows customizing how the source connects to the SPIFFE
    /// Workload API and how X.509 material is managed (e.g. endpoint selection,
    /// reconnection behavior, resource limits).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use spiffe::X509Source;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let source = X509Source::builder()
    ///     .endpoint("unix:///tmp/spire-agent/public/api.sock".try_into()?)
    ///     .build()
    ///     .await?;
    ///
    /// # Ok(())
    /// # }
    /// ```
    pub fn builder() -> X509SourceBuilder {
        X509SourceBuilder::new()
    }

    /// Returns a handle for receiving update notifications.
    ///
    /// The handle yields a monotonically increasing sequence number on each
    /// successful update to the X.509 context. This can be used to detect when
    /// the context has changed without polling.
    ///
    /// **Note:** The initial sequence number is 0. Notifications are only sent
    /// for rotations that occur after initial synchronization completes. The initial
    /// sync does not trigger a notification.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use spiffe::X509Source;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let source = X509Source::new().await?;
    /// let mut updates = source.updated();
    /// // Wait for the first update notification
    /// updates.changed().await?;
    /// println!("Update sequence: {}", updates.last());
    /// # Ok(())
    /// # }
    /// ```
    pub fn updated(&self) -> X509SourceUpdates {
        X509SourceUpdates {
            rx: self.inner.update_rx.clone(),
        }
    }

    /// Returns `true` if the source appears healthy and can likely provide an SVID.
    ///
    /// This method checks that:
    /// - The source is not closed or cancelled
    /// - There are SVIDs available
    /// - An SVID can be selected (either via picker or default)
    ///
    /// **Note:** This check is inherently racy. Between calling `is_healthy()` and
    /// `svid()`, the source may be shut down or the context may change. Use this
    /// for best-effort health checks (e.g., monitoring), not for synchronization.
    /// If you need a guaranteed check, call `svid()` directly and handle the error.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use spiffe::X509Source;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let source = X509Source::new().await?;
    ///
    /// if source.is_healthy() {
    ///     println!("Source appears healthy");
    /// } else {
    ///     println!("Source is unhealthy");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn is_healthy(&self) -> bool {
        if self.inner.closed.load(Ordering::Acquire) || self.inner.cancel.is_cancelled() {
            return false;
        }

        let ctx = self.inner.x509_context.load();
        // Check that an SVID can actually be selected (using shared selection logic).
        // This ensures is_healthy() matches the same selection logic used by svid().
        select_svid(&ctx, self.inner.svid_picker.as_deref()).is_some()
    }

    /// Returns the current X.509 context (SVID + bundles) as a single value.
    ///
    /// # Errors
    ///
    /// Returns an [`X509SourceError`] if the X.509 context is not available or
    /// cannot be constructed.
    pub fn x509_context(&self) -> Result<Arc<X509Context>, X509SourceError> {
        self.assert_open()?;
        Ok(self.inner.x509_context.load_full())
    }

    /// Returns the current X.509 SVID selected by the picker (or default).
    ///
    /// # Errors
    ///
    /// Returns [`X509SourceError`] if the source is closed or no SVID is available.
    pub fn svid(&self) -> Result<Arc<X509Svid>, X509SourceError> {
        self.assert_open()?;

        let ctx = self.inner.x509_context.load();
        select_svid(&ctx, self.inner.svid_picker.as_deref()).ok_or_else(|| {
            self.inner.record_error(MetricsErrorKind::NoSuitableSvid);
            X509SourceError::NoSuitableSvid
        })
    }

    /// Returns the current SVID, or `None` if unavailable.
    ///
    /// This is a convenience method that returns `None` instead of an error
    /// when the SVID cannot be retrieved. Use this when `None` is an acceptable
    /// value for your use case.
    ///
    /// **Note:** This method swallows all errors, including `Closed`. If you need
    /// to detect shutdown, use [`X509Source::svid`] instead.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use spiffe::X509Source;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let source = X509Source::new().await?;
    ///
    /// if let Some(svid) = source.try_svid() {
    ///     println!("Got SVID: {}", svid.spiffe_id());
    /// } else {
    ///     println!("No SVID available");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn try_svid(&self) -> Option<Arc<X509Svid>> {
        self.svid().ok()
    }

    /// Returns the current X.509 bundle set.
    ///
    /// # Errors
    ///
    /// Returns [`X509SourceError`] if the source is closed.
    pub fn bundle_set(&self) -> Result<Arc<X509BundleSet>, X509SourceError> {
        self.assert_open()?;
        Ok(self.inner.x509_context.load().bundle_set().clone())
    }

    /// Returns the current bundle for the trust domain, or `None` if unavailable.
    ///
    /// This is a convenience method that returns `None` instead of an error
    /// when the bundle cannot be retrieved. Use this when `None` is an acceptable
    /// value for your use case.
    ///
    /// **Note:** This method swallows all errors, including `Closed`. If you need
    /// to detect shutdown, use [`X509Source::bundle_for_trust_domain`] instead.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use spiffe::{TrustDomain, X509Source};
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let source = X509Source::new().await?;
    /// let trust_domain = TrustDomain::new("example.org")?;
    ///
    /// if let Some(bundle) = source.try_bundle_for_trust_domain(&trust_domain) {
    ///     println!("Got bundle for {}", trust_domain);
    /// } else {
    ///     println!("No bundle available for {}", trust_domain);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn try_bundle_for_trust_domain(&self, td: &TrustDomain) -> Option<Arc<X509Bundle>> {
        self.bundle_for_trust_domain(td).ok().flatten()
    }

    /// Cancels background tasks and waits for termination.
    ///
    /// This method is idempotent. Calling it multiple times is safe and has no
    /// additional effect after the first invocation.
    ///
    /// The shutdown request is best-effort. Background tasks are signaled to stop
    /// and awaited before returning.
    ///
    /// **Note:** This method may wait indefinitely if background tasks don't respond.
    /// For production use, prefer [`X509Source::shutdown_with_timeout`] or
    /// [`X509Source::shutdown_configured`].
    pub async fn shutdown(&self) {
        if self.inner.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        self.inner.cancel.cancel();

        if let Some(handle) = self.inner.supervisor.lock().await.take() {
            if let Err(_e) = handle.await {
                warn!(
                    "Error joining supervisor task during shutdown: error={}",
                    _e
                );
                self.inner
                    .record_error(MetricsErrorKind::SupervisorJoinFailed);
            }
        }
    }

    /// Cancels background tasks and waits for termination with a timeout.
    ///
    /// This method attempts graceful shutdown first: it signals cancellation and
    /// waits up to `timeout` for the supervisor task to complete. If the timeout
    /// is exceeded, the task is forcefully aborted.
    ///
    /// This method is idempotent. Calling it multiple times is safe and has no
    /// additional effect after the first invocation.
    ///
    /// # Errors
    ///
    /// Returns [`X509SourceError::ShutdownTimeout`] if graceful shutdown does not
    /// complete within the timeout and the task must be aborted.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use spiffe::X509Source;
    /// use std::time::Duration;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let source = X509Source::new().await?;
    /// // Shutdown with 10 second timeout (graceful, then abort if needed)
    /// source.shutdown_with_timeout(Duration::from_secs(10)).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn shutdown_with_timeout(&self, timeout: Duration) -> Result<(), X509SourceError> {
        if self.inner.closed.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        self.inner.cancel.cancel();

        let Some(mut handle) = self.inner.supervisor.lock().await.take() else {
            return Ok(());
        };

        match tokio::time::timeout(timeout, &mut handle).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_e)) => {
                warn!(
                    "Error joining supervisor task during shutdown: error={}",
                    _e
                );
                self.inner
                    .record_error(MetricsErrorKind::SupervisorJoinFailed);
                Ok(())
            }
            Err(_) => {
                warn!("Shutdown timeout exceeded; aborting supervisor task");
                handle.abort();
                // Wait for the abort to take effect
                let _ = handle.await;
                Err(X509SourceError::ShutdownTimeout)
            }
        }
    }

    /// Cancels background tasks and waits for termination using the configured timeout.
    ///
    /// This is a convenience method that uses the timeout configured in the builder.
    /// If no timeout was configured, this method will wait indefinitely (same as `shutdown()`).
    ///
    /// # Errors
    ///
    /// Returns [`X509SourceError::ShutdownTimeout`] if the configured shutdown timeout is exceeded.
    pub async fn shutdown_configured(&self) -> Result<(), X509SourceError> {
        if let Some(timeout) = self.inner.shutdown_timeout {
            self.shutdown_with_timeout(timeout).await
        } else {
            self.shutdown().await;
            Ok(())
        }
    }
}

impl X509Source {
    pub(super) async fn build_with(
        make_client: ClientFactory,
        svid_picker: Option<Box<dyn SvidPicker>>,
        reconnect: ReconnectConfig,
        limits: ResourceLimits,
        metrics: Option<Arc<dyn MetricsRecorder>>,
        shutdown_timeout: Option<Duration>,
    ) -> Result<X509Source, X509SourceError> {
        let reconnect = super::builder::normalize_reconnect(reconnect);

        let (update_tx, update_rx) = watch::channel(0u64);
        let cancel = CancellationToken::new();

        let initial_ctx = initial_sync_with_retry(
            &make_client,
            svid_picker.as_deref(),
            &cancel,
            reconnect,
            limits,
            metrics.as_deref(),
        )
        .await?;

        let inner = Arc::new(Inner {
            x509_context: ArcSwap::from(initial_ctx),
            svid_picker,
            reconnect,
            make_client,
            limits,
            metrics,
            shutdown_timeout,
            closed: AtomicBool::new(false),
            cancel,
            update_seq: AtomicU64::new(0),
            update_tx,
            update_rx,
            supervisor: Mutex::new(None),
        });

        let task_inner = Arc::clone(&inner);
        let token = task_inner.cancel.clone();
        let handle = tokio::spawn(async move {
            task_inner.run_update_supervisor(token).await;
        });

        *inner.supervisor.lock().await = Some(handle);

        Ok(Self { inner })
    }

    /// Test-only constructor that creates an `X509Source` with a provided initial context
    /// without spawning the supervisor task or performing initial sync.
    ///
    /// This allows deterministic unit tests without requiring a real Workload API client.
    #[cfg(test)]
    pub(super) fn new_for_test(
        initial_ctx: Arc<X509Context>,
        reconnect: ReconnectConfig,
        limits: ResourceLimits,
        metrics: Option<Arc<dyn MetricsRecorder>>,
        svid_picker: Option<Box<dyn SvidPicker>>,
    ) -> X509Source {
        // Normalize reconnect config at the boundary (same as new_with)
        let reconnect = super::builder::normalize_reconnect(reconnect);

        let (update_tx, update_rx) = watch::channel(0u64);
        let cancel = CancellationToken::new();

        let make_client: ClientFactory =
            Arc::new(|| Box::pin(async move { Err(WorkloadApiError::EmptyResponse) }));

        let inner = Inner {
            x509_context: ArcSwap::from(initial_ctx),
            svid_picker,
            reconnect,
            make_client,
            limits,
            metrics,
            shutdown_timeout: None,
            closed: AtomicBool::new(false),
            cancel,
            update_seq: AtomicU64::new(0),
            update_tx,
            update_rx,
            supervisor: Mutex::new(None),
        };

        Self {
            inner: Arc::new(inner),
        }
    }

    fn assert_open(&self) -> Result<(), X509SourceError> {
        if self.inner.closed.load(Ordering::Acquire) || self.inner.cancel.is_cancelled() {
            return Err(X509SourceError::Closed);
        }
        Ok(())
    }
}

impl Inner {
    pub(super) fn record_error(&self, kind: MetricsErrorKind) {
        if let Some(metrics) = self.metrics.as_deref() {
            metrics.record_error(kind);
        }
    }

    pub(super) fn record_update(&self) {
        if let Some(metrics) = self.metrics.as_deref() {
            metrics.record_update();
        }
    }

    pub(super) fn apply_update(&self, new_ctx: Arc<X509Context>) -> Result<(), X509SourceError> {
        // validate_and_select() already records limit-specific metrics and NoSuitableSvid.
        // We only record UpdateRejected here if validation fails, and the supervisor loop
        // should NOT record it again to avoid double-counting.
        match self.validate_and_select(&new_ctx) {
            Ok(()) => {
                self.x509_context.store(new_ctx);
                self.record_update();
                self.notify_update();
                Ok(())
            }
            Err(e) => {
                // Record UpdateRejected for any validation failure (limit metrics already recorded in validate_and_select).
                self.record_error(MetricsErrorKind::UpdateRejected);
                Err(e)
            }
        }
    }

    pub(super) fn notify_update(&self) {
        let next = self.update_seq.fetch_add(1, Ordering::Relaxed) + 1;
        let _ = self.update_tx.send(next);
    }

    pub(super) fn validate_and_select(&self, ctx: &X509Context) -> Result<(), X509SourceError> {
        validate_context(
            ctx,
            self.svid_picker.as_deref(),
            self.limits,
            self.metrics.as_deref(),
        )
    }
}

impl Drop for X509Source {
    fn drop(&mut self) {
        // Best-effort cancellation. Do not block in Drop.
        self.inner.cancel.cancel();
    }
}

impl SvidSource for X509Source {
    type Item = X509Svid;
    type Error = X509SourceError;

    fn svid(&self) -> Result<Arc<Self::Item>, Self::Error> {
        X509Source::svid(self)
    }
}

impl BundleSource for X509Source {
    type Item = X509Bundle;
    type Error = X509SourceError;

    fn bundle_for_trust_domain(
        &self,
        trust_domain: &TrustDomain,
    ) -> Result<Option<Arc<Self::Item>>, Self::Error> {
        self.assert_open()?;
        let ctx = self.inner.x509_context.load();
        Ok(ctx.bundle_set().get(trust_domain))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::super::errors::MetricsErrorKind;
    use super::super::metrics::MetricsRecorder;
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::sync::watch;

    #[tokio::test]
    async fn test_wait_for_immediate_satisfaction() {
        let (tx, rx) = watch::channel(5u64);
        let mut updates = X509SourceUpdates { rx };

        // Predicate is already satisfied (current value is 5, which is > 3)
        let result = updates.wait_for(|&seq| seq > 3).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 5);

        // Update the value
        let _ = tx.send(10);

        // Wait for predicate to be satisfied again (should return immediately with new value)
        let result = updates.wait_for(|&seq| seq > 8).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 10);
    }

    #[tokio::test]
    async fn test_wait_for_waits_when_not_satisfied() {
        let (tx, rx) = watch::channel(1u64);
        let mut updates = X509SourceUpdates { rx };

        // Spawn a task to update the value after a short delay
        let tx_clone = tx.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let _ = tx_clone.send(5);
        });

        // Predicate is not satisfied initially (1 is not > 3)
        // Should wait and then return when value becomes 5
        let result = tokio::time::timeout(Duration::from_secs(1), updates.wait_for(|&seq| seq > 3))
            .await
            .expect("Should complete within timeout");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 5);
    }

    #[tokio::test]
    async fn test_updated_only_notifies_on_rotations_after_initial_sync() {
        // Verify that updated().changed() only notifies on rotations after initial sync,
        // not on the initial sync itself. The initial sequence number is 0.
        let (tx, rx) = watch::channel(0u64);
        let mut updates = X509SourceUpdates { rx: rx.clone() };

        // Initial value is 0, so changed() should wait for an update
        let tx_clone = tx.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            // Simulate first rotation after initial sync
            let _ = tx_clone.send(1);
        });

        // Should wait and then return when value becomes 1 (first rotation)
        let result = tokio::time::timeout(Duration::from_secs(1), updates.changed())
            .await
            .expect("Should complete within timeout");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1);
        assert_eq!(updates.last(), 1);
    }

    #[tokio::test]
    async fn test_updated_initial_sequence_is_zero() {
        // Verify that the initial sequence number is 0
        let (_tx, rx) = watch::channel(0u64);
        let updates = X509SourceUpdates { rx };
        assert_eq!(updates.last(), 0);
    }

    /// Test metrics recorder that counts error recordings by kind.
    struct TestMetricsRecorder {
        counts: Arc<Mutex<HashMap<MetricsErrorKind, u64>>>,
    }

    impl TestMetricsRecorder {
        fn new() -> Self {
            Self {
                counts: Arc::new(Mutex::new(HashMap::new())),
            }
        }

        fn count(&self, kind: MetricsErrorKind) -> u64 {
            *self.counts.lock().unwrap().get(&kind).unwrap_or(&0)
        }
    }

    impl MetricsRecorder for TestMetricsRecorder {
        fn record_update(&self) {}
        fn record_reconnect(&self) {}
        fn record_error(&self, kind: MetricsErrorKind) {
            *self.counts.lock().unwrap().entry(kind).or_insert(0) += 1;
        }
    }

    #[test]
    fn test_metrics_recorded_exactly_once_per_rejected_update() {
        // Verify that UpdateRejected and limit metrics are recorded exactly once
        // per rejected update, with no double-counting.
        use super::super::builder::{ReconnectConfig, ResourceLimits};
        use crate::workload_api::x509_context::X509Context;
        use crate::{TrustDomain, X509Bundle, X509BundleSet, X509Svid};
        use std::sync::Arc;

        // Load test fixture SVID
        let cert_bytes = include_bytes!("../../tests/testdata/svid/x509/1-svid-chain.der");
        let key_bytes = include_bytes!("../../tests/testdata/svid/x509/1-key.der");
        let svid = Arc::new(X509Svid::parse_from_der(cert_bytes, key_bytes).unwrap());

        let metrics = Arc::new(TestMetricsRecorder::new());
        let limits = ResourceLimits {
            max_svids: Some(100),
            max_bundles: Some(0), // Limit that will be exceeded
            max_bundle_der_bytes: Some(1000),
        };

        // Create a context with 1 bundle (exceeds max_bundles=0)
        let trust_domain = TrustDomain::new("example.org").unwrap();
        let bundle = X509Bundle::new(trust_domain.clone());
        let mut bundle_set = X509BundleSet::new();
        bundle_set.add_bundle(bundle);

        let ctx = X509Context::new([svid], Arc::new(bundle_set));

        // Create source using test seam
        let source = X509Source::new_for_test(
            Arc::new(X509Context::new([], Arc::new(X509BundleSet::new()))),
            ReconnectConfig::default(),
            limits,
            Some(metrics.clone()),
            None,
        );

        // Apply update that should be rejected due to max_bundles limit
        let result = source.inner.apply_update(Arc::new(ctx));

        // Should fail with ResourceLimitExceeded
        assert!(matches!(
            result,
            Err(X509SourceError::ResourceLimitExceeded {
                kind: super::super::errors::LimitKind::MaxBundles,
                ..
            })
        ));

        // Verify metrics recorded exactly once
        assert_eq!(metrics.count(MetricsErrorKind::LimitMaxBundles), 1);
        assert_eq!(metrics.count(MetricsErrorKind::UpdateRejected), 1);
        // Verify no other limit metrics were recorded
        assert_eq!(metrics.count(MetricsErrorKind::LimitMaxSvids), 0);
        assert_eq!(metrics.count(MetricsErrorKind::LimitMaxBundleDerBytes), 0);
    }

    #[test]
    fn test_new_with_normalizes_reconnect_config() {
        // Verify that X509Source::new_with() normalizes reconnect config at the authoritative boundary.
        use super::super::builder::{ReconnectConfig, ResourceLimits};
        use crate::workload_api::x509_context::X509Context;
        use crate::{X509BundleSet, X509Svid};
        use std::sync::Arc;
        use std::time::Duration;

        // Load test fixture SVID
        let cert_bytes = include_bytes!("../../tests/testdata/svid/x509/1-svid-chain.der");
        let key_bytes = include_bytes!("../../tests/testdata/svid/x509/1-key.der");
        let svid = Arc::new(X509Svid::parse_from_der(cert_bytes, key_bytes).unwrap());

        // Create a context with valid SVID and bundle
        let ctx = X509Context::new([svid], Arc::new(X509BundleSet::new()));

        // Create reconnect config with inverted min/max (min > max)
        let inverted_reconnect = ReconnectConfig {
            min_backoff: Duration::from_secs(10),
            max_backoff: Duration::from_secs(1),
        };

        // Create source using test seam with inverted reconnect config
        let source = X509Source::new_for_test(
            Arc::new(ctx),
            inverted_reconnect,
            ResourceLimits::default(),
            None,
            None,
        );

        // Verify that reconnect config was normalized (swapped)
        assert_eq!(source.inner.reconnect.min_backoff, Duration::from_secs(1));
        assert_eq!(source.inner.reconnect.max_backoff, Duration::from_secs(10));
    }

    #[test]
    fn test_initial_sync_validation_records_correct_metrics() {
        // Verify that validation records limit metrics and NoSuitableSvid,
        // but does NOT record UpdateRejected (that's recorded by apply_update).
        use super::super::builder::ResourceLimits;
        use super::super::limits::validate_context;
        use crate::workload_api::x509_context::X509Context;
        use crate::{TrustDomain, X509Bundle, X509BundleSet, X509Svid};
        use std::sync::Arc;

        // Load test fixture SVID
        let cert_bytes = include_bytes!("../../tests/testdata/svid/x509/1-svid-chain.der");
        let key_bytes = include_bytes!("../../tests/testdata/svid/x509/1-key.der");
        let svid = Arc::new(X509Svid::parse_from_der(cert_bytes, key_bytes).unwrap());

        let metrics = Arc::new(TestMetricsRecorder::new());
        let limits = ResourceLimits {
            max_svids: Some(100),
            max_bundles: Some(0), // Limit that will be exceeded
            max_bundle_der_bytes: Some(1000),
        };

        // Create a context with 1 bundle (exceeds max_bundles=0)
        let trust_domain = TrustDomain::new("example.org").unwrap();
        let bundle = X509Bundle::new(trust_domain.clone());
        let mut bundle_set = X509BundleSet::new();
        bundle_set.add_bundle(bundle);

        let ctx = X509Context::new([svid], Arc::new(bundle_set));

        // Validate context (simulating validation used in both initial sync and updates)
        let result = validate_context(
            &ctx,
            None, // No picker
            limits,
            Some(metrics.as_ref() as &dyn MetricsRecorder),
        );

        // Should fail with ResourceLimitExceeded
        assert!(matches!(
            result,
            Err(X509SourceError::ResourceLimitExceeded {
                kind: super::super::errors::LimitKind::MaxBundles,
                ..
            })
        ));

        // Verify limit metric was recorded
        assert_eq!(metrics.count(MetricsErrorKind::LimitMaxBundles), 1);
        // Verify UpdateRejected was NOT recorded (that's recorded by apply_update, not validate_context)
        assert_eq!(metrics.count(MetricsErrorKind::UpdateRejected), 0);
        // Verify no other limit metrics were recorded
        assert_eq!(metrics.count(MetricsErrorKind::LimitMaxSvids), 0);
        assert_eq!(metrics.count(MetricsErrorKind::LimitMaxBundleDerBytes), 0);
    }

    #[test]
    fn test_resource_limits_unlimited() {
        // Verify that ResourceLimits::unlimited() creates limits with all fields set to None.
        use super::super::builder::ResourceLimits;

        let unlimited = ResourceLimits::unlimited();
        assert_eq!(unlimited.max_svids, None);
        assert_eq!(unlimited.max_bundles, None);
        assert_eq!(unlimited.max_bundle_der_bytes, None);
    }

    #[test]
    fn test_resource_limits_default_limits() {
        // Verify that ResourceLimits::default_limits() creates limits with conservative defaults.
        use super::super::builder::ResourceLimits;

        let limits = ResourceLimits::default_limits();
        assert_eq!(limits.max_svids, Some(100));
        assert_eq!(limits.max_bundles, Some(200));
        assert_eq!(limits.max_bundle_der_bytes, Some(4 * 1024 * 1024)); // 4MB
    }

    #[test]
    fn test_resource_limits_mixed() {
        // Verify that ResourceLimits can have mixed unlimited and limited fields.
        use super::super::builder::ResourceLimits;

        let mixed = ResourceLimits {
            max_svids: Some(50),
            max_bundles: None,                       // Unlimited
            max_bundle_der_bytes: Some(1024 * 1024), // 1MB
        };

        assert_eq!(mixed.max_svids, Some(50));
        assert_eq!(mixed.max_bundles, None);
        assert_eq!(mixed.max_bundle_der_bytes, Some(1024 * 1024));
    }
}
