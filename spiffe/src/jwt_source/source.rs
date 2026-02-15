use super::builder::{JwtSourceBuilder, ReconnectConfig, ResourceLimits};
use super::errors::{JwtSourceError, MetricsErrorKind};
use super::limits::validate_bundle_set;
use super::metrics::MetricsRecorder;
use super::supervisor::initial_sync_with_retry;
use super::types::ClientFactory;
use crate::bundle::BundleSource;
use crate::prelude::warn;
use crate::workload_api::WorkloadApiClient;
use crate::{JwtBundle, JwtBundleSet, JwtSvid, SpiffeId, TrustDomain};
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

/// Handle for receiving update notifications from a [`JwtSource`].
///
/// This type wraps the underlying notification mechanism and provides a clean
/// API for detecting when the JWT bundle set has been updated.
///
/// Cloning this handle creates another receiver that shares the same update
/// stream. Each receiver observes the latest sequence number; if a receiver
/// is slow to consume updates, intermediate sequence numbers may be skipped
/// (this is the standard behavior of `watch` channels).
///
/// # Examples
///
/// ```no_run
/// # use spiffe::JwtSource;
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let source = JwtSource::new().await?;
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
pub struct JwtSourceUpdates {
    rx: watch::Receiver<u64>,
}

impl JwtSourceUpdates {
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
    /// Returns [`JwtSourceError::Closed`] if the source has been shut down
    /// or the internal update task has terminated. This can occur due to:
    /// - Explicit shutdown via [`JwtSource::shutdown`] or [`JwtSource::shutdown_with_timeout`]
    /// - Internal task termination (e.g., supervisor task panic)
    pub async fn changed(&mut self) -> Result<u64, JwtSourceError> {
        self.rx
            .changed()
            .await
            .map_err(|watch::error::RecvError { .. }| JwtSourceError::Closed)?;
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
    pub async fn wait_for<F>(&mut self, mut f: F) -> Result<u64, JwtSourceError>
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

/// Live source of JWT bundles from the SPIFFE Workload API.
///
/// `JwtSource` performs an initial sync before returning from [`JwtSource::new`] or
/// [`JwtSourceBuilder::build`]. Updates are applied atomically and can be observed via
/// [`JwtSource::updated`].
///
/// The source automatically:
/// - Maintains a cached view of the latest JWT bundles
/// - Handles bundle rotation transparently
/// - Reconnects with exponential backoff on transient failures
/// - Validates resource limits before publishing updates
///
/// Unlike X.509 SVIDs which are streamed continuously, JWT SVIDs are fetched on-demand
/// with specific audiences. Use [`JwtSource::get_jwt_svid`] to fetch JWT SVIDs as needed.
///
/// Use [`JwtSource::shutdown`] or [`JwtSource::shutdown_configured`] to stop background tasks.
///
#[derive(Clone, Debug)]
pub struct JwtSource {
    inner: Arc<Inner>,
}

pub(super) struct Inner {
    // Atomically replaced, last-known-good JWT bundle set.
    bundle_set: ArcSwap<JwtBundleSet>,
    limits: ResourceLimits,

    // Cached client for on-demand SVID fetching (recreated on failure).
    // Uses Option to allow lazy initialization.
    // Protected by Mutex to prevent concurrent creation.
    cached_client: ArcSwap<Option<Arc<WorkloadApiClient>>>,
    client_creation_mutex: Mutex<()>,

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
    pub(super) const fn reconnect(&self) -> ReconnectConfig {
        self.reconnect
    }
    pub(super) fn metrics(&self) -> Option<&dyn MetricsRecorder> {
        self.metrics.as_deref()
    }
    pub(super) fn make_client(&self) -> &ClientFactory {
        &self.make_client
    }

    /// Gets the cached client or creates a new one if not available.
    ///
    /// This method is safe to call concurrently. If multiple tasks call this
    /// simultaneously when the cache is empty, only one will create the client;
    /// the others will wait and reuse the newly created client.
    pub(super) async fn get_or_recreate_client(
        &self,
    ) -> Result<Arc<WorkloadApiClient>, JwtSourceError> {
        // Fast path: check cache first
        let cached = self.cached_client.load();
        if let Some(client) = cached.as_ref() {
            return Ok(Arc::clone(client));
        }

        // Slow path: serialize client creation to avoid races
        let _guard = self.client_creation_mutex.lock().await;

        // Double-check: another task might have created it while we waited
        let cached = self.cached_client.load();
        if let Some(client) = cached.as_ref() {
            return Ok(Arc::clone(client));
        }

        // We're the first, create the client
        self.recreate_client_inner().await
    }

    /// Recreates the cached client and stores it atomically.
    ///
    /// This method should be called when the cached client fails or becomes invalid.
    /// It serializes creation to avoid concurrent recreation.
    pub(super) async fn recreate_client(&self) -> Result<Arc<WorkloadApiClient>, JwtSourceError> {
        let _guard = self.client_creation_mutex.lock().await;
        self.recreate_client_inner().await
    }

    /// Internal helper that actually creates and stores the client.
    /// Must be called while holding `client_creation_mutex`.
    async fn recreate_client_inner(&self) -> Result<Arc<WorkloadApiClient>, JwtSourceError> {
        let client = (self.make_client)().await.map_err(JwtSourceError::Source)?;
        let client_arc = Arc::new(client);
        self.cached_client
            .store(Arc::new(Some(Arc::clone(&client_arc))));
        Ok(client_arc)
    }
}

impl Debug for Inner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtSource")
            .field("bundle_set", &"<ArcSwap<JwtBundleSet>>")
            .field(
                "cached_client",
                &"<ArcSwap<Option<Arc<WorkloadApiClient>>>>",
            )
            .field("client_creation_mutex", &"<Mutex<()>>")
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

impl JwtSource {
    /// Creates a `JwtSource` using the default Workload API endpoint.
    ///
    /// The endpoint is resolved from `SPIFFE_ENDPOINT_SOCKET`.
    ///
    /// On success, the returned source is already synchronized with the agent and will keep
    /// updating in the background until it is closed.
    ///
    /// # Errors
    ///
    /// Returns a [`JwtSourceError`] if:
    /// - the Workload API endpoint cannot be resolved or connected to,
    /// - the initial synchronization with the Workload API does not complete successfully.
    pub async fn new() -> Result<Self, JwtSourceError> {
        JwtSourceBuilder::new().build().await
    }

    /// Creates a builder for configuring a [`JwtSource`].
    ///
    /// The builder allows customizing how the source connects to the SPIFFE
    /// Workload API and how JWT material is managed (e.g. endpoint selection,
    /// reconnection behavior, resource limits).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use spiffe::jwt_source::JwtSource;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let source = JwtSource::builder()
    ///     .endpoint("unix:///tmp/spire-agent/public/api.sock")
    ///     .build()
    ///     .await?;
    ///
    /// # Ok(())
    /// # }
    /// ```
    pub fn builder() -> JwtSourceBuilder {
        JwtSourceBuilder::new()
    }

    /// Returns a handle for receiving update notifications.
    ///
    /// The handle yields a monotonically increasing sequence number on each
    /// successful update to the JWT bundle set. This can be used to detect when
    /// the bundle set has changed without polling.
    ///
    /// **Note:** The initial sequence number is 0. Notifications are only sent
    /// for rotations that occur after initial synchronization completes. The initial
    /// sync does not trigger a notification.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use spiffe::JwtSource;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let source = JwtSource::new().await?;
    /// let mut updates = source.updated();
    /// // Wait for the first update notification
    /// updates.changed().await?;
    /// println!("Update sequence: {}", updates.last());
    /// # Ok(())
    /// # }
    /// ```
    pub fn updated(&self) -> JwtSourceUpdates {
        JwtSourceUpdates {
            rx: self.inner.update_rx.clone(),
        }
    }

    /// Returns `true` if the source appears healthy and can likely provide bundles.
    ///
    /// This method checks that:
    /// - The source is not closed or cancelled
    /// - There are bundles available
    ///
    /// **Note:** This check is inherently racy. Between calling `is_healthy()` and
    /// `bundle_set()`, the source may be shut down or the bundle set may change. Use this
    /// for best-effort health checks (e.g., monitoring), not for synchronization.
    /// If you need a guaranteed check, call `bundle_set()` directly and handle the error.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use spiffe::JwtSource;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let source = JwtSource::new().await?;
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

        let bundle_set = self.inner.bundle_set.load();
        !bundle_set.is_empty()
    }

    /// Returns the current JWT bundle set.
    ///
    /// # Errors
    ///
    /// Returns a [`JwtSourceError`] if the source is closed.
    pub fn bundle_set(&self) -> Result<Arc<JwtBundleSet>, JwtSourceError> {
        self.assert_open()?;
        Ok(self.inner.bundle_set.load_full())
    }

    /// Returns the current bundle for the trust domain, or `None` if unavailable.
    ///
    /// Returns `None` instead of an error
    /// when the bundle cannot be retrieved. Use this when `None` is an acceptable
    /// value for your use case.
    ///
    /// **Note:** This method swallows all errors, including `Closed`. If you need
    /// to detect shutdown, use [`JwtSource::bundle_for_trust_domain`] instead.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use spiffe::{TrustDomain, JwtSource};
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let source = JwtSource::new().await?;
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
    pub fn try_bundle_for_trust_domain(&self, td: &TrustDomain) -> Option<Arc<JwtBundle>> {
        self.bundle_for_trust_domain(td).ok().flatten()
    }

    /// Fetches a JWT SVID for the given audience.
    ///
    /// Unlike X.509 SVIDs which are streamed continuously, JWT SVIDs are fetched
    /// on-demand with specific audiences. This method makes a one-shot request to
    /// the Workload API to fetch a JWT SVID.
    ///
    /// # Errors
    ///
    /// Returns a [`JwtSourceError`] if:
    /// - the source is closed
    /// - the Workload API request fails
    /// - no SVID is returned or the SVID cannot be parsed
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use spiffe::JwtSource;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let source = JwtSource::new().await?;
    ///
    /// // Fetch a JWT SVID for specific audiences
    /// let jwt_svid = source.get_jwt_svid(&["service-a", "service-b"]).await?;
    /// println!("SPIFFE ID: {}", jwt_svid.spiffe_id());
    ///
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_jwt_svid<I>(&self, audience: I) -> Result<JwtSvid, JwtSourceError>
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
    {
        self.get_jwt_svid_with_id(audience, None).await
    }

    /// Fetches a JWT SVID for the given audience and optional SPIFFE ID.
    ///
    /// This method automatically retries once if the initial request fails (e.g., due to
    /// a closed connection). On retry, the cached client is recreated to handle transient
    /// connection issues.
    ///
    /// # Errors
    ///
    /// Returns a [`JwtSourceError`] if:
    /// - the source is closed
    /// - the Workload API request fails (after retry)
    /// - no SVID is returned or the SVID cannot be parsed
    /// # Examples
    ///
    /// ```no_run
    /// # use spiffe::JwtSource;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let source = JwtSource::new().await?;
    ///
    /// // Fetch for a specific SPIFFE ID
    /// let spiffe_id = "spiffe://example.org/myservice".parse()?;
    /// let jwt_svid = source.get_jwt_svid_with_id(&["service-a"], Some(&spiffe_id)).await?;
    /// # Ok(())
    /// # }
    pub async fn get_jwt_svid_with_id<I>(
        &self,
        audience: I,
        spiffe_id: Option<&SpiffeId>,
    ) -> Result<JwtSvid, JwtSourceError>
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
    {
        self.assert_open()?;

        // Collect audience into Vec to allow reuse on retry
        let audience_vec: Vec<String> = audience
            .into_iter()
            .map(|a| a.as_ref().to_string())
            .collect();

        let client = self.inner.get_or_recreate_client().await?;

        // Try to fetch the SVID
        match client.fetch_jwt_svid(&audience_vec, spiffe_id).await {
            Ok(svid) => Ok(svid),
            Err(_e) => {
                // On failure, invalidate the cached client and try once more
                // This handles transient connection issues (e.g., connection closed)
                self.assert_open()?; // Check if closed before retry
                let new_client = self.inner.recreate_client().await?;
                new_client
                    .fetch_jwt_svid(&audience_vec, spiffe_id)
                    .await
                    .map_err(JwtSourceError::FetchJwtSvid)
            }
        }
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
    /// For production use, use [`JwtSource::shutdown_with_timeout`] or
    /// [`JwtSource::shutdown_configured`].
    pub async fn shutdown(&self) {
        if self.inner.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        self.inner.cancel.cancel();

        if let Some(handle) = self.inner.supervisor.lock().await.take() {
            if let Err(e) = handle.await {
                warn!("Error joining supervisor task during shutdown: error={e}");
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
    /// Returns [`JwtSourceError::ShutdownTimeout`] if graceful shutdown does not
    /// complete within the timeout and the task must be aborted.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use spiffe::JwtSource;
    /// use std::time::Duration;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let source = JwtSource::new().await?;
    /// // Shutdown with 10 second timeout (graceful, then abort if needed)
    /// source.shutdown_with_timeout(Duration::from_secs(10)).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn shutdown_with_timeout(&self, timeout: Duration) -> Result<(), JwtSourceError> {
        if self.inner.closed.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        self.inner.cancel.cancel();

        let Some(mut handle) = self.inner.supervisor.lock().await.take() else {
            return Ok(());
        };

        match tokio::time::timeout(timeout, &mut handle).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => {
                warn!("Error joining supervisor task during shutdown: error={e}");
                self.inner
                    .record_error(MetricsErrorKind::SupervisorJoinFailed);
                Ok(())
            }
            Err(_) => {
                warn!("Shutdown timeout exceeded; aborting supervisor task");
                handle.abort();
                // Wait for the abort to take effect
                let _unused: Result<_, _> = handle.await;
                Err(JwtSourceError::ShutdownTimeout)
            }
        }
    }

    /// Cancels background tasks and waits for termination using the configured timeout.
    ///
    /// Uses the timeout configured in the builder.
    /// If no timeout was configured, this method will wait indefinitely (same as `shutdown()`).
    ///
    /// # Errors
    ///
    /// Returns [`JwtSourceError::ShutdownTimeout`] if the configured shutdown timeout is exceeded.
    pub async fn shutdown_configured(&self) -> Result<(), JwtSourceError> {
        if let Some(timeout) = self.inner.shutdown_timeout {
            self.shutdown_with_timeout(timeout).await
        } else {
            self.shutdown().await;
            Ok(())
        }
    }
}

impl JwtSource {
    pub(super) async fn build_with(
        make_client: ClientFactory,
        reconnect: ReconnectConfig,
        limits: ResourceLimits,
        metrics: Option<Arc<dyn MetricsRecorder>>,
        shutdown_timeout: Option<Duration>,
    ) -> Result<Self, JwtSourceError> {
        let reconnect = super::builder::normalize_reconnect(reconnect);

        let (update_tx, update_rx) = watch::channel(0u64);
        let cancel = CancellationToken::new();

        let initial_bundle_set =
            initial_sync_with_retry(&make_client, &cancel, reconnect, limits, metrics.as_deref())
                .await?;

        // Create initial client for on-demand SVID fetching.
        // Retry once after a short delay if the first attempt fails, because the
        // initial sync (which also creates clients internally) already succeeded,
        // so a failure here is likely transient.
        let initial_client = match make_client().await {
            Ok(c) => c,
            Err(_first_err) => {
                tokio::time::sleep(reconnect.min_backoff).await;
                make_client().await.map_err(JwtSourceError::Source)?
            }
        };
        let initial_client_arc = Arc::new(initial_client);

        let inner = Arc::new(Inner {
            bundle_set: ArcSwap::from(initial_bundle_set),
            cached_client: ArcSwap::from(Arc::new(Some(initial_client_arc))),
            client_creation_mutex: Mutex::new(()),
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

    /// Test-only constructor that creates a `JwtSource` with a provided initial bundle set
    /// without spawning the supervisor task or performing initial sync.
    ///
    /// This allows deterministic unit tests without requiring a real Workload API client.
    #[cfg(test)]
    pub(super) fn new_for_test(
        initial_bundle_set: Arc<JwtBundleSet>,
        reconnect: ReconnectConfig,
        limits: ResourceLimits,
        metrics: Option<Arc<dyn MetricsRecorder>>,
    ) -> Self {
        // Normalize reconnect config at the boundary (same as build_with)
        let reconnect = super::builder::normalize_reconnect(reconnect);

        let (update_tx, update_rx) = watch::channel(0u64);
        let cancel = CancellationToken::new();

        let make_client: ClientFactory =
            Arc::new(|| Box::pin(async move { Err(WorkloadApiError::EmptyResponse) }));

        let inner = Inner {
            bundle_set: ArcSwap::from(initial_bundle_set),
            cached_client: ArcSwap::from(Arc::new(None)),
            client_creation_mutex: Mutex::new(()),
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

    fn assert_open(&self) -> Result<(), JwtSourceError> {
        if self.inner.closed.load(Ordering::Acquire) || self.inner.cancel.is_cancelled() {
            return Err(JwtSourceError::Closed);
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

    pub(super) fn apply_update(
        &self,
        new_bundle_set: Arc<JwtBundleSet>,
    ) -> Result<(), JwtSourceError> {
        // validate_bundle_set() already records limit-specific metrics.
        // We only record UpdateRejected here if validation fails, and the supervisor loop
        // should NOT record it again to avoid double-counting.
        match self.validate_bundle_set(&new_bundle_set) {
            Ok(()) => {
                self.bundle_set.store(new_bundle_set);
                self.record_update();
                self.notify_update();
                Ok(())
            }
            Err(e) => {
                // Record UpdateRejected for any validation failure (limit metrics already recorded in validate_bundle_set).
                self.record_error(MetricsErrorKind::UpdateRejected);
                Err(e)
            }
        }
    }

    pub(super) fn notify_update(&self) {
        let next = self.update_seq.fetch_add(1, Ordering::Relaxed) + 1;
        let _unused: Result<_, _> = self.update_tx.send(next);
    }

    pub(super) fn validate_bundle_set(
        &self,
        bundle_set: &JwtBundleSet,
    ) -> Result<(), JwtSourceError> {
        validate_bundle_set(bundle_set, self.limits, self.metrics.as_deref())
    }
}

impl Drop for JwtSource {
    fn drop(&mut self) {
        // Best-effort cancellation. Do not block in Drop.
        self.inner.cancel.cancel();
    }
}

impl BundleSource for JwtSource {
    type Item = JwtBundle;
    type Error = JwtSourceError;

    fn bundle_for_trust_domain(
        &self,
        trust_domain: &TrustDomain,
    ) -> Result<Option<Arc<Self::Item>>, Self::Error> {
        self.assert_open()?;
        let bundle_set = self.inner.bundle_set.load();
        Ok(bundle_set.get(trust_domain))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::jwt::JwtAuthority;
    use std::collections::HashMap;
    use std::sync::Mutex;

    fn jwk_with_kid(kid: &str) -> JwtAuthority {
        let json = format!(
            r#"{{
                "kty": "oct",
                "kid": "{kid}",
                "k": "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
            }}"#
        );
        JwtAuthority::from_jwk_json(json.as_bytes()).expect("valid JWK JSON")
    }

    fn create_test_bundle_set() -> Arc<JwtBundleSet> {
        let trust_domain = TrustDomain::new("example.org").unwrap();
        let mut bundle = JwtBundle::new(trust_domain);
        bundle.add_jwt_authority(jwk_with_kid("kid-1"));
        let mut bundle_set = JwtBundleSet::new();
        bundle_set.add_bundle(bundle);
        Arc::new(bundle_set)
    }

    #[tokio::test]
    async fn test_wait_for_immediate_satisfaction() {
        let (tx, rx) = watch::channel(5u64);
        let mut updates = JwtSourceUpdates { rx };

        // Predicate is already satisfied (current value is 5, which is > 3)
        let result = updates.wait_for(|&seq| seq > 3).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 5);

        // Update the value
        let _unused: Result<_, _> = tx.send(10);

        // Wait for predicate to be satisfied again (should return immediately with new value)
        let result = updates.wait_for(|&seq| seq > 8).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 10);
    }

    #[tokio::test]
    async fn test_wait_for_waits_when_not_satisfied() {
        let (tx, rx) = watch::channel(1u64);
        let mut updates = JwtSourceUpdates { rx };

        // Spawn a task to update the value after a short delay
        let tx_clone = tx.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let _unused: Result<_, _> = tx_clone.send(5);
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
        let mut updates = JwtSourceUpdates { rx: rx.clone() };

        // Initial value is 0, so changed() should wait for an update
        let tx_clone = tx.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            // Simulate first rotation after initial sync
            let _unused: Result<_, _> = tx_clone.send(1);
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
        let updates = JwtSourceUpdates { rx };
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
        use super::super::builder::ResourceLimits;
        use crate::bundle::jwt::JwtBundle;

        let metrics = Arc::new(TestMetricsRecorder::new());
        let limits = ResourceLimits {
            max_bundles: Some(0), // Limit that will be exceeded
            max_bundle_jwks_bytes: Some(1000),
        };

        // Create a bundle set with 1 bundle (exceeds max_bundles=0)
        let trust_domain = TrustDomain::new("example.org").unwrap();
        let mut bundle = JwtBundle::new(trust_domain);
        bundle.add_jwt_authority(jwk_with_kid("kid-1"));
        let mut bundle_set = JwtBundleSet::new();
        bundle_set.add_bundle(bundle);

        // Create source using test seam
        let source = {
            let metrics = Arc::clone(&metrics);
            JwtSource::new_for_test(
                Arc::new(JwtBundleSet::new()),
                ReconnectConfig::default(),
                limits,
                Some(metrics),
            )
        };

        // Apply update that should be rejected due to max_bundles limit
        let result = source.inner.apply_update(Arc::new(bundle_set));

        // Should fail with ResourceLimitExceeded
        assert!(matches!(
            result,
            Err(JwtSourceError::ResourceLimitExceeded {
                kind: super::super::errors::LimitKind::MaxBundles,
                ..
            })
        ));

        // Verify metrics recorded exactly once
        assert_eq!(metrics.count(MetricsErrorKind::LimitMaxBundles), 1);
        assert_eq!(metrics.count(MetricsErrorKind::UpdateRejected), 1);
        // Verify no other limit metrics were recorded
        assert_eq!(metrics.count(MetricsErrorKind::LimitMaxBundleJwksBytes), 0);
    }

    #[test]
    fn test_new_with_normalizes_reconnect_config() {
        // Verify that JwtSource::build_with() normalizes reconnect config at the authoritative boundary.
        use super::super::builder::ResourceLimits;
        use std::time::Duration;

        let initial_bundle_set = create_test_bundle_set();

        // Create reconnect config with inverted min/max (min > max)
        let inverted_reconnect = ReconnectConfig {
            min_backoff: Duration::from_secs(10),
            max_backoff: Duration::from_secs(1),
        };

        // Create source using test seam with inverted reconnect config
        let source = JwtSource::new_for_test(
            initial_bundle_set,
            inverted_reconnect,
            ResourceLimits::default(),
            None,
        );

        // Verify that reconnect config was normalized (swapped)
        assert_eq!(source.inner.reconnect.min_backoff, Duration::from_secs(1));
        assert_eq!(source.inner.reconnect.max_backoff, Duration::from_secs(10));
    }

    #[test]
    fn test_initial_sync_validation_records_correct_metrics() {
        // Verify that validation records limit metrics,
        // but does NOT record UpdateRejected (that's recorded by apply_update).
        use super::super::builder::ResourceLimits;
        use super::super::limits::validate_bundle_set;

        let metrics = Arc::new(TestMetricsRecorder::new());
        let limits = ResourceLimits {
            max_bundles: Some(0), // Limit that will be exceeded
            max_bundle_jwks_bytes: Some(1000),
        };

        // Create a bundle set with 1 bundle (exceeds max_bundles=0)
        let trust_domain = TrustDomain::new("example.org").unwrap();
        let mut bundle = JwtBundle::new(trust_domain);
        bundle.add_jwt_authority(jwk_with_kid("kid-1"));
        let mut bundle_set = JwtBundleSet::new();
        bundle_set.add_bundle(bundle);

        // Validate bundle set (simulating validation used in both initial sync and updates)
        let result = validate_bundle_set(&bundle_set, limits, Some(metrics.as_ref()));

        // Should fail with ResourceLimitExceeded
        assert!(matches!(
            result,
            Err(JwtSourceError::ResourceLimitExceeded {
                kind: super::super::errors::LimitKind::MaxBundles,
                ..
            })
        ));

        // Verify limit metric was recorded
        assert_eq!(metrics.count(MetricsErrorKind::LimitMaxBundles), 1);
        // Verify UpdateRejected was NOT recorded (that's recorded by apply_update, not validate_bundle_set)
        assert_eq!(metrics.count(MetricsErrorKind::UpdateRejected), 0);
        // Verify no other limit metrics were recorded
        assert_eq!(metrics.count(MetricsErrorKind::LimitMaxBundleJwksBytes), 0);
    }

    #[test]
    fn test_resource_limits_unlimited() {
        // Verify that ResourceLimits::unlimited() creates limits with all fields set to None.
        use super::super::builder::ResourceLimits;

        let unlimited = ResourceLimits::unlimited();
        assert_eq!(unlimited.max_bundles, None);
        assert_eq!(unlimited.max_bundle_jwks_bytes, None);
    }

    #[test]
    fn test_resource_limits_default_limits() {
        // Verify that ResourceLimits::default_limits() creates limits with conservative defaults.
        use super::super::builder::ResourceLimits;

        let limits = ResourceLimits::default_limits();
        assert_eq!(limits.max_bundles, Some(200));
        assert_eq!(limits.max_bundle_jwks_bytes, Some(4 * 1024 * 1024)); // 4MB
    }

    #[test]
    fn test_resource_limits_mixed() {
        // Verify that ResourceLimits can have mixed unlimited and limited fields.
        use super::super::builder::ResourceLimits;

        let mixed = ResourceLimits {
            max_bundles: Some(50),
            max_bundle_jwks_bytes: None, // Unlimited
        };

        assert_eq!(mixed.max_bundles, Some(50));
        assert_eq!(mixed.max_bundle_jwks_bytes, None);
    }
}
