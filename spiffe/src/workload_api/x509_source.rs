//! Live X.509 SVID and bundle source backed by the SPIFFE Workload API.
//!
//! `X509Source` performs an initial synchronization before becoming usable, then watches the
//! Workload API for rotations. Transient failures are handled by reconnecting with backoff.
//!
//! If multiple X.509 SVIDs are available, `X509Source` selects one using the configured picker
//! (or the Workload API "default" SVID if no picker is set).
//!
//! Use [`X509Source::updated`] to subscribe to change notifications, and [`X509Source::shutdown`]
//! to stop background tasks.
//!
//! # Example
//!
//! ```no_run
//! use spiffe::{TrustDomain, X509Source};
//! use crate::spiffe::bundle::BundleSource;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//! let source = X509Source::new().await?;
//!
//! // Selected SVID (default or picker).
//! let svid = source.svid()?;
//!
//! let td = TrustDomain::new("example.org")?;
//! let bundle = source
//!     .bundle_for_trust_domain(&td)?
//!     .ok_or("missing bundle")?;
//!
//! # Ok(())
//! # }
//! ```

use crate::bundle::BundleSource;
use crate::endpoint::Endpoint;
use crate::svid::SvidSource;
use crate::workload_api::error::WorkloadApiError;
use crate::{TrustDomain, WorkloadApiClient, X509Bundle, X509BundleSet, X509Context, X509Svid};
use std::fmt;

use arc_swap::ArcSwap;

#[cfg(not(feature = "tracing"))]
use log::{debug, info, warn};
#[cfg(feature = "tracing")]
use tracing::{debug, info, warn};

use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use thiserror::Error;
use tokio::sync::{watch, Mutex};
use tokio::task::JoinHandle;
use tokio::time::{sleep, Duration};
use tokio_stream::StreamExt;
use tokio_util::sync::CancellationToken;

/// Strategy for selecting an X.509 SVID when multiple SVIDs are available.
///
/// Implement this trait to customize SVID selection logic. The picker is called whenever
/// a new X.509 context is received from the Workload API.
///
/// # Example
///
/// ```no_run
/// use spiffe::X509Svid;
/// use std::sync::Arc;
/// use spiffe::workload_api::x509_source::SvidPicker;
///
/// #[derive(Debug)]
/// struct HintPicker {
///     hint: String,
/// }
///
/// impl SvidPicker for HintPicker {
///     fn pick_svid(&self, svids: &[Arc<X509Svid>]) -> Option<usize> {
///         svids.iter()
///             .position(|svid| svid.hint() == Some(&self.hint))
///     }
/// }
/// ```
pub trait SvidPicker: Debug + Send + Sync {
    /// Selects an SVID from the provided slice by returning its index.
    ///
    /// Returning `None` indicates that no suitable SVID could be selected.
    /// Returning `Some(index)` selects the SVID at the given index in the slice.
    fn pick_svid(&self, svids: &[Arc<X509Svid>]) -> Option<usize>;
}

/// Reconnect/backoff configuration.
///
/// When the Workload API connection fails, the source will retry with exponential
/// backoff between `min_backoff` and `max_backoff`. The backoff includes small jitter
/// to prevent synchronized reconnect storms in high-concurrency scenarios.
#[derive(Clone, Copy, Debug)]
pub struct ReconnectConfig {
    /// Initial delay before retrying.
    pub min_backoff: Duration,
    /// Maximum delay between retries.
    pub max_backoff: Duration,
}

impl Default for ReconnectConfig {
    fn default() -> Self {
        Self {
            min_backoff: Duration::from_millis(200),
            max_backoff: Duration::from_secs(10),
        }
    }
}

/// Use this value for "unlimited".
pub const UNLIMITED: usize = usize::MAX;

/// Resource limits for defense-in-depth security.
///
/// These are best-effort limits intended to prevent accidental or malicious resource exhaustion.
/// Limits are enforced before a new context is published to consumers.
#[derive(Clone, Copy, Debug)]
pub struct ResourceLimits {
    /// Maximum number of SVIDs allowed in a context.
    pub max_svids: usize,
    /// Maximum number of bundles allowed in a bundle set.
    pub max_bundles: usize,
    /// Maximum "bundle size" in bytes.
    ///
    /// Definition: sum of DER byte lengths of all authority certificates in a bundle.
    pub max_bundle_der_bytes: usize,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            // Conservative defaults; typical workloads are far below these.
            max_svids: 100,
            max_bundles: 200,
            max_bundle_der_bytes: 4 * 1024 * 1024, // 4MB
        }
    }
}

/// Error kinds for structured metrics reporting.
///
/// Use these stable, low-cardinality labels when recording metrics.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum MetricsErrorKind {
    /// Failed to create a Workload API client.
    ClientCreation,
    /// Failed to connect to the Workload API stream.
    StreamConnect,
    /// Error occurred while reading from the stream.
    StreamError,
    /// The Workload API stream ended unexpectedly.
    StreamEnded,
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
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClientCreation => "client_creation",
            Self::StreamConnect => "stream_connect",
            Self::StreamError => "stream_error",
            Self::StreamEnded => "stream_ended",
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

/// Trait for recording metrics from `X509Source`.
///
/// Implement this trait to integrate with your metrics system (e.g., Prometheus, `StatsD`).
/// Prefer stable, low-cardinality labels when recording metrics.
///
/// # Example
///
/// ```no_run
/// use spiffe::{MetricsErrorKind, MetricsRecorder};
/// use std::sync::Arc;
///
/// struct MyMetrics;
///
/// impl MetricsRecorder for MyMetrics {
///     fn record_update(&self) {
///         // Record update metric
///     }
///
///     fn record_reconnect(&self) {
///         // Record reconnect metric
///     }
///
///     fn record_error(&self, kind: MetricsErrorKind) {
///         // Record error metric with kind label
///         println!("Error: {}", kind.as_str());
///     }
/// }
///
/// let metrics = Arc::new(MyMetrics);
/// // Use with X509SourceBuilder::with_metrics()
/// ```
pub trait MetricsRecorder: Send + Sync {
    /// Records that an X.509 context update occurred.
    fn record_update(&self);

    /// Records that a reconnection attempt occurred.
    fn record_reconnect(&self);

    /// Records an error with a structured error kind.
    fn record_error(&self, kind: MetricsErrorKind);
}

/// Errors returned by `X509Source`.
#[derive(Debug, Error)]
pub enum X509SourceError {
    /// Failed to retrieve or refresh X.509 material from the source.
    #[error("x509 source error: {0}")]
    Source(#[from] WorkloadApiError),

    /// No SVID could be selected from the received context.
    ///
    /// This can occur when:
    /// - The picker rejects all available SVIDs
    /// - No default SVID is available and no picker is configured
    #[error("no suitable svid found")]
    NoSuitableSvid,

    /// The source was closed.
    #[error("source is closed")]
    Closed,

    /// The workload API stream ended.
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

/// The kind of resource limit that was exceeded.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
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
    /// This is a convenience method that repeatedly calls `changed()` until
    /// the predicate returns `true`.
    ///
    /// # Errors
    ///
    /// Returns an error if the source has been closed.
    pub async fn wait_for<F>(&mut self, mut f: F) -> Result<u64, X509SourceError>
    where
        F: FnMut(&u64) -> bool,
    {
        loop {
            let seq = self.changed().await?;
            if f(&seq) {
                return Ok(seq);
            }
        }
    }
}

type ClientFuture =
    Pin<Box<dyn Future<Output = Result<WorkloadApiClient, WorkloadApiError>> + Send + 'static>>;
type ClientFactory = Arc<dyn Fn() -> ClientFuture + Send + Sync + 'static>;

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
pub struct X509Source {
    x509_context: ArcSwap<X509Context>,

    svid_picker: Option<Box<dyn SvidPicker>>,
    reconnect: ReconnectConfig,
    make_client: ClientFactory,
    limits: ResourceLimits,
    metrics: Option<Arc<dyn MetricsRecorder>>,
    shutdown_timeout: Option<Duration>,

    closed: AtomicBool,
    cancel: CancellationToken,

    update_seq: AtomicU64,
    update_tx: watch::Sender<u64>,
    update_rx: watch::Receiver<u64>,

    supervisor: Mutex<Option<JoinHandle<()>>>,
}

impl Debug for X509Source {
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

/// Builder for [`X509Source`].
///
/// Use this when you need explicit configuration (socket path, picker, backoff, resource limits).
///
/// # Example
///
/// ```no_run
/// use spiffe::{ResourceLimits, X509SourceBuilder, UNLIMITED};
/// use std::time::Duration;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let source = X509SourceBuilder::new()
///     .with_endpoint("unix:/tmp/spire-agent/public/api.sock")
///     .with_reconnect_backoff(Duration::from_secs(1), Duration::from_secs(30))
///     .with_resource_limits(ResourceLimits {
///         max_svids: 100,
///         max_bundles: 500,
///         max_bundle_der_bytes: 5 * 1024 * 1024, // 5MB
///     })
///     .build()
///     .await?;
/// # Ok(())
/// # }
/// ```
pub struct X509SourceBuilder {
    svid_picker: Option<Box<dyn SvidPicker>>,
    reconnect: ReconnectConfig,
    make_client: Option<ClientFactory>,
    limits: ResourceLimits,
    metrics: Option<Arc<dyn MetricsRecorder>>,
    shutdown_timeout: Option<Duration>,
}

impl Debug for X509SourceBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X509SourceBuilder")
            .field(
                "svid_picker",
                &self.svid_picker.as_ref().map(|_| "<SvidPicker>"),
            )
            .field("reconnect", &self.reconnect)
            .field("limits", &self.limits)
            .field(
                "make_client",
                &self.make_client.as_ref().map(|_| "<ClientFactory>"),
            )
            .field(
                "metrics",
                &self.metrics.as_ref().map(|_| "<MetricsRecorder>"),
            )
            .field("shutdown_timeout", &self.shutdown_timeout)
            .finish()
    }
}

impl Default for X509SourceBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl X509SourceBuilder {
    /// Creates a new `X509SourceBuilder`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use spiffe::X509SourceBuilder;
    /// # use std::time::Duration;
    ///
    /// let builder = X509SourceBuilder::new()
    ///     .with_endpoint("unix:/tmp/spire-agent/public/api.sock")
    ///     .with_reconnect_backoff(Duration::from_secs(1), Duration::from_secs(30));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn new() -> Self {
        Self {
            svid_picker: None,
            reconnect: ReconnectConfig::default(),
            make_client: None,
            limits: ResourceLimits::default(),
            metrics: None,
            shutdown_timeout: Some(Duration::from_secs(30)),
        }
    }

    /// Sets the Workload API endpoint.
    ///
    /// Accepts either a filesystem path (e.g. `/tmp/spire-agent/public/api.sock`)
    /// or a full URI (e.g. `unix:///tmp/spire-agent/public/api.sock`).
    ///
    /// **Note:** Endpoint validation is deferred until `build()` is called. For early
    /// validation, use [`X509SourceBuilder::try_with_endpoint`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use spiffe::X509SourceBuilder;
    ///
    /// let builder = X509SourceBuilder::new()
    ///     .with_endpoint("unix:/tmp/spire-agent/public/api.sock");
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub fn with_endpoint(mut self, endpoint: impl AsRef<str>) -> Self {
        let endpoint: Arc<str> = Arc::from(endpoint.as_ref());

        let factory: ClientFactory = Arc::new(move || {
            let endpoint = endpoint.clone();
            Box::pin(async move { WorkloadApiClient::connect_to(endpoint).await })
        });

        self.make_client = Some(factory);
        self
    }

    /// Sets the Workload API endpoint with early validation.
    ///
    /// This method parses and validates the endpoint immediately, allowing you to
    /// catch configuration errors at build time rather than when the source connects.
    ///
    /// # Errors
    ///
    /// Returns an error if the endpoint string cannot be parsed as a valid SPIFFE
    /// endpoint (see [`Endpoint::parse`] for validation rules).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use spiffe::X509SourceBuilder;
    ///
    /// let builder = X509SourceBuilder::new()
    ///     .try_with_endpoint("unix:/tmp/spire-agent/public/api.sock")?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn try_with_endpoint(
        mut self,
        endpoint: impl AsRef<str>,
    ) -> Result<Self, crate::endpoint::EndpointError> {
        let endpoint_str = endpoint.as_ref();
        let _parsed = Endpoint::parse(endpoint_str)?;

        // If parsing succeeds, use the same factory pattern as with_endpoint
        let endpoint: Arc<str> = Arc::from(endpoint_str);
        let factory: ClientFactory = Arc::new(move || {
            let endpoint = endpoint.clone();
            Box::pin(async move { WorkloadApiClient::connect_to(endpoint).await })
        });

        self.make_client = Some(factory);
        Ok(self)
    }

    /// Sets a custom client factory.
    #[must_use]
    pub fn with_client_factory(mut self, factory: ClientFactory) -> Self {
        self.make_client = Some(factory);
        self
    }

    /// Sets a custom SVID selection strategy.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::sync::Arc;
    ///
    /// use spiffe::workload_api::x509_source::{SvidPicker, X509SourceBuilder};
    /// use spiffe::X509Svid;
    ///
    /// #[derive(Debug)]
    /// struct HintPicker {
    ///     hint: String,
    /// }
    ///
    /// impl SvidPicker for HintPicker {
    ///     fn pick_svid(&self, svids: &[Arc<X509Svid>]) -> Option<usize> {
    ///         svids
    ///             .iter()
    ///             .position(|svid: &Arc<X509Svid>| svid.hint() == Some(self.hint.as_str()))
    ///     }
    /// }
    ///
    /// let _builder = X509SourceBuilder::new()
    ///     .with_picker(HintPicker {
    ///         hint: "internal".to_string(),
    ///     });
    /// ```
    #[must_use]
    pub fn with_picker<P>(mut self, picker: P) -> Self
    where
        P: SvidPicker + 'static,
    {
        self.svid_picker = Some(Box::new(picker));
        self
    }

    /// Sets the reconnect backoff range.
    ///
    /// When the Workload API connection fails, the source will retry with exponential
    /// backoff between `min_backoff` and `max_backoff`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use spiffe::X509SourceBuilder;
    /// use std::time::Duration;
    ///
    /// let builder = X509SourceBuilder::new()
    ///     .with_reconnect_backoff(Duration::from_secs(1), Duration::from_secs(60));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub fn with_reconnect_backoff(mut self, min_backoff: Duration, max_backoff: Duration) -> Self {
        self.reconnect = ReconnectConfig {
            min_backoff,
            max_backoff,
        };
        self
    }

    /// Sets resource limits for defense-in-depth security.
    ///
    /// These limits prevent resource exhaustion from malicious or misconfigured agents.
    /// Default limits are reasonable for most use cases.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use spiffe::{ResourceLimits, X509SourceBuilder, UNLIMITED};
    ///
    /// let limits = ResourceLimits {
    ///     max_svids: 50,
    ///     max_bundles: 500,
    ///     max_bundle_der_bytes: 5 * 1024 * 1024, // 5MB
    /// };
    /// let builder = X509SourceBuilder::new().with_resource_limits(limits);
    ///
    /// // Or disable limits:
    /// let unlimited = ResourceLimits {
    ///     max_svids: UNLIMITED,
    ///     max_bundles: UNLIMITED,
    ///     max_bundle_der_bytes: UNLIMITED,
    /// };
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub fn with_resource_limits(mut self, limits: ResourceLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Sets an optional metrics recorder for observability.
    ///
    /// The metrics recorder will be called to record updates, reconnections, and errors.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use spiffe::{MetricsErrorKind, MetricsRecorder, X509SourceBuilder};
    /// use std::sync::Arc;
    ///
    /// struct MyMetrics;
    ///
    /// impl MetricsRecorder for MyMetrics {
    ///     fn record_update(&self) { /* ... */ }
    ///     fn record_reconnect(&self) { /* ... */ }
    ///     fn record_error(&self, _kind: MetricsErrorKind) { /* ... */ }
    /// }
    ///
    /// let metrics = Arc::new(MyMetrics);
    /// let builder = X509SourceBuilder::new().with_metrics(metrics);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub fn with_metrics(mut self, metrics: Arc<dyn MetricsRecorder>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Sets the shutdown timeout.
    ///
    /// When `shutdown_with_timeout()` or `shutdown_configured()` is called, it will wait
    /// at most this duration for background tasks to complete. If `None`, shutdown will
    /// wait indefinitely (same as `shutdown()`).
    ///
    /// Default is 30 seconds.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use spiffe::X509SourceBuilder;
    /// use std::time::Duration;
    ///
    /// let builder = X509SourceBuilder::new()
    ///     .with_shutdown_timeout(Some(Duration::from_secs(10)));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub fn with_shutdown_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.shutdown_timeout = timeout;
        self
    }

    /// Builds a ready-to-use [`X509Source`].
    ///
    /// On success, the returned source has completed an initial synchronization with
    /// the Workload API and will continue updating in the background.
    ///
    /// # Errors
    ///
    /// Returns an [`X509SourceError`] if the Workload API endpoint cannot be resolved
    /// or connected to, the initial synchronization fails, or no suitable X.509 SVID
    /// can be selected.
    pub async fn build(self) -> Result<Arc<X509Source>, X509SourceError> {
        let make_client = self.make_client.unwrap_or_else(|| {
            Arc::new(|| Box::pin(async { WorkloadApiClient::connect_env().await }))
        });

        X509Source::new_with(
            make_client,
            self.svid_picker,
            self.reconnect,
            self.limits,
            self.metrics,
            self.shutdown_timeout,
        )
        .await
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
    pub async fn new() -> Result<Arc<Self>, X509SourceError> {
        X509SourceBuilder::new().build().await
    }

    /// Returns a handle for receiving update notifications.
    ///
    /// The handle yields a monotonically increasing sequence number on each
    /// successful update to the X.509 context. This can be used to detect when
    /// the context has changed without polling.
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
            rx: self.update_rx.clone(),
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
        if self.closed.load(Ordering::Acquire) || self.cancel.is_cancelled() {
            return false;
        }

        let ctx = self.x509_context.load();
        if ctx.svids().is_empty() {
            return false;
        }

        // Check that an SVID can actually be selected.
        if let Some(ref picker) = self.svid_picker {
            picker.pick_svid(ctx.svids()).is_some()
        } else {
            ctx.default_svid().is_some()
        }
    }

    /// Returns the current X.509 context (SVID + bundles) as a single value.
    ///
    /// # Errors
    ///
    /// Returns an [`X509SourceError`] if the X.509 context is not available or
    /// cannot be constructed.
    pub fn x509_context(&self) -> Result<Arc<X509Context>, X509SourceError> {
        self.assert_open()?;
        Ok(self.x509_context.load_full())
    }

    /// Returns the current X.509 SVID selected by the picker (or default).
    ///
    /// # Errors
    ///
    /// Returns [`X509SourceError`] if the source is closed or no SVID is available.
    pub fn svid(&self) -> Result<Arc<X509Svid>, X509SourceError> {
        self.assert_open()?;

        let ctx = self.x509_context.load();
        let selected = if let Some(ref picker) = self.svid_picker {
            picker
                .pick_svid(ctx.svids())
                .and_then(|idx| ctx.svids().get(idx))
                .cloned()
                .ok_or_else(|| {
                    self.record_error(MetricsErrorKind::NoSuitableSvid);
                    X509SourceError::NoSuitableSvid
                })?
        } else {
            ctx.default_svid().cloned().ok_or_else(|| {
                self.record_error(MetricsErrorKind::NoSuitableSvid);
                X509SourceError::NoSuitableSvid
            })?
        };

        Ok(selected)
    }

    /// Returns the current SVID, or `None` if unavailable.
    ///
    /// This is a convenience method that returns `None` instead of an error
    /// when the SVID cannot be retrieved. Use this when `None` is an acceptable
    /// value for your use case.
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
        Ok(self.x509_context.load().bundle_set().clone())
    }

    /// Returns the current bundle for the trust domain, or `None` if unavailable.
    ///
    /// This is a convenience method that returns `None` instead of an error
    /// when the bundle cannot be retrieved. Use this when `None` is an acceptable
    /// value for your use case.
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
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        self.cancel.cancel();

        if let Some(handle) = self.supervisor.lock().await.take() {
            if let Err(e) = handle.await {
                warn!("Error joining supervisor task during shutdown: {e}");
                self.record_error(MetricsErrorKind::SupervisorJoinFailed);
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
        if self.closed.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        self.cancel.cancel();

        let Some(mut handle) = self.supervisor.lock().await.take() else {
            return Ok(());
        };

        match tokio::time::timeout(timeout, &mut handle).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => {
                warn!("Error joining supervisor task during shutdown: {e}");
                self.record_error(MetricsErrorKind::SupervisorJoinFailed);
                Ok(())
            }
            Err(_) => {
                // Join didn't complete in time; abort the task and wait for it to stop.
                warn!("Shutdown timeout exceeded; aborting supervisor task");
                handle.abort();
                // Wait for the abort to take effect (this should complete quickly)
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
        if let Some(timeout) = self.shutdown_timeout {
            self.shutdown_with_timeout(timeout).await
        } else {
            self.shutdown().await;
            Ok(())
        }
    }
}

impl Drop for X509Source {
    fn drop(&mut self) {
        // Best-effort cancellation. Do not block in Drop.
        self.cancel.cancel();
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
        let ctx = self.x509_context.load();
        Ok(ctx.bundle_set().get(trust_domain))
    }
}

// ------------------------- internal -------------------------

impl X509Source {
    async fn new_with(
        make_client: ClientFactory,
        svid_picker: Option<Box<dyn SvidPicker>>,
        reconnect: ReconnectConfig,
        limits: ResourceLimits,
        metrics: Option<Arc<dyn MetricsRecorder>>,
        shutdown_timeout: Option<Duration>,
    ) -> Result<Arc<X509Source>, X509SourceError> {
        let (update_tx, update_rx) = watch::channel(0u64);
        let cancel = CancellationToken::new();

        // Initial sync must produce a usable + validated context.
        let initial_ctx = initial_sync_with_retry(
            &make_client,
            svid_picker.as_deref(),
            &cancel,
            reconnect,
            limits,
            metrics.as_deref(),
        )
        .await?;

        let src = Arc::new(Self {
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

        let cloned = Arc::clone(&src);
        let token = cloned.cancel.clone();
        let handle = tokio::spawn(async move {
            cloned.run_update_supervisor(token).await;
        });

        *src.supervisor.lock().await = Some(handle);
        Ok(src)
    }

    fn assert_open(&self) -> Result<(), X509SourceError> {
        if self.closed.load(Ordering::Acquire) || self.cancel.is_cancelled() {
            return Err(X509SourceError::Closed);
        }
        Ok(())
    }

    fn record_error(&self, kind: MetricsErrorKind) {
        if let Some(metrics) = self.metrics.as_deref() {
            metrics.record_error(kind);
        }
    }

    fn record_update(&self) {
        if let Some(metrics) = self.metrics.as_deref() {
            metrics.record_update();
        }
    }

    fn record_reconnect(&self) {
        if let Some(metrics) = self.metrics.as_deref() {
            metrics.record_reconnect();
        }
    }

    fn notify_update(&self) {
        let next = self.update_seq.fetch_add(1, Ordering::Relaxed) + 1;
        let _ = self.update_tx.send(next);
    }

    fn validate_and_select(&self, ctx: &X509Context) -> Result<(), X509SourceError> {
        // Validate limits and record specific metric if limit is exceeded.
        if let Err(e) = validate_limits(ctx, self.limits) {
            if let X509SourceError::ResourceLimitExceeded { kind, .. } = &e {
                let metric_kind = match kind {
                    LimitKind::MaxSvids => MetricsErrorKind::LimitMaxSvids,
                    LimitKind::MaxBundles => MetricsErrorKind::LimitMaxBundles,
                    LimitKind::MaxBundleDerBytes => MetricsErrorKind::LimitMaxBundleDerBytes,
                };
                self.record_error(metric_kind);
            }
            return Err(e);
        }

        // Ensure the context is usable for callers (picker/default can select).
        if let Some(ref picker) = self.svid_picker {
            picker
                .pick_svid(ctx.svids())
                .and_then(|idx| ctx.svids().get(idx))
                .ok_or_else(|| {
                    self.record_error(MetricsErrorKind::NoSuitableSvid);
                    X509SourceError::NoSuitableSvid
                })?;
        } else {
            ctx.default_svid().ok_or_else(|| {
                self.record_error(MetricsErrorKind::NoSuitableSvid);
                X509SourceError::NoSuitableSvid
            })?;
        }

        Ok(())
    }

    fn apply_update(&self, new_ctx: Arc<X509Context>) -> Result<(), X509SourceError> {
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

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(skip(self, cancellation_token))
    )]
    async fn run_update_supervisor(&self, cancellation_token: CancellationToken) {
        let mut backoff = self.reconnect.min_backoff;

        loop {
            if cancellation_token.is_cancelled() {
                debug!("Cancellation signal received; stopping updates.");
                return;
            }

            let client = match (self.make_client)().await {
                Ok(c) => {
                    backoff = self.reconnect.min_backoff;
                    c
                }
                Err(e) => {
                    warn!("Failed to create WorkloadApiClient: {e}. Retrying in {backoff:?}.");
                    self.record_error(MetricsErrorKind::ClientCreation);
                    self.record_reconnect();
                    if sleep_or_cancel(&cancellation_token, backoff).await {
                        return;
                    }
                    backoff = next_backoff(backoff, self.reconnect.max_backoff);
                    continue;
                }
            };

            let mut stream = match client.stream_x509_contexts().await {
                Ok(s) => {
                    info!("Connected to Workload API X509 context stream.");
                    backoff = self.reconnect.min_backoff;
                    s
                }
                Err(e) => {
                    warn!(
                        "Failed to connect to Workload API stream: {e}. Retrying in {backoff:?}."
                    );
                    self.record_error(MetricsErrorKind::StreamConnect);
                    self.record_reconnect();
                    if sleep_or_cancel(&cancellation_token, backoff).await {
                        return;
                    }
                    backoff = next_backoff(backoff, self.reconnect.max_backoff);
                    continue;
                }
            };

            loop {
                if cancellation_token.is_cancelled() {
                    debug!("Cancellation signal received; stopping update loop.");
                    return;
                }

                match stream.next().await {
                    Some(Ok(ctx)) => {
                        // Drop invalid updates and keep last-good snapshot.
                        // apply_update() already records UpdateRejected and limit-specific metrics.
                        match self.apply_update(Arc::new(ctx)) {
                            Ok(()) => debug!("X509 context updated."),
                            Err(e) => {
                                warn!("Rejected X509 context update: {e}");
                                // Metrics already recorded in apply_update(), do not double-count.
                                // continue streaming
                            }
                        }
                    }
                    Some(Err(e)) => {
                        warn!("Workload API stream error: {e}. Reconnecting...");
                        self.record_error(MetricsErrorKind::StreamError);
                        self.record_reconnect();
                        break;
                    }
                    None => {
                        warn!("Workload API stream ended. Reconnecting...");
                        self.record_error(MetricsErrorKind::StreamEnded);
                        self.record_reconnect();
                        break;
                    }
                }
            }

            if sleep_or_cancel(&cancellation_token, backoff).await {
                return;
            }
            backoff = next_backoff(backoff, self.reconnect.max_backoff);
        }
    }
}

fn validate_limits(ctx: &X509Context, limits: ResourceLimits) -> Result<(), X509SourceError> {
    if limits.max_svids != UNLIMITED {
        let actual = ctx.svids().len();
        if actual > limits.max_svids {
            return Err(X509SourceError::ResourceLimitExceeded {
                kind: LimitKind::MaxSvids,
                limit: limits.max_svids,
                actual,
            });
        }
    }

    if limits.max_bundles != UNLIMITED {
        let actual = ctx.bundle_set().len();
        if actual > limits.max_bundles {
            return Err(X509SourceError::ResourceLimitExceeded {
                kind: LimitKind::MaxBundles,
                limit: limits.max_bundles,
                actual,
            });
        }
    }

    if limits.max_bundle_der_bytes != UNLIMITED {
        for (_, bundle) in ctx.bundle_set().iter() {
            // Definition: sum of DER bytes of all authority certificates in the bundle.
            let actual: usize = bundle
                .authorities()
                .iter()
                .map(|cert| cert.as_bytes().len())
                .sum();

            if actual > limits.max_bundle_der_bytes {
                return Err(X509SourceError::ResourceLimitExceeded {
                    kind: LimitKind::MaxBundleDerBytes,
                    limit: limits.max_bundle_der_bytes,
                    actual,
                });
            }
        }
    }

    Ok(())
}

async fn initial_sync_with_retry(
    make_client: &ClientFactory,
    picker: Option<&dyn SvidPicker>,
    cancel: &CancellationToken,
    reconnect: ReconnectConfig,
    limits: ResourceLimits,
    metrics: Option<&dyn MetricsRecorder>,
) -> Result<Arc<X509Context>, X509SourceError> {
    let mut backoff = reconnect.min_backoff;

    loop {
        if cancel.is_cancelled() {
            return Err(X509SourceError::Closed);
        }

        match try_sync_once(make_client, picker, limits, metrics).await {
            Ok(v) => return Ok(v),
            Err(e) => {
                warn!("Initial sync failed: {e}. Retrying in {backoff:?}.");
                // Metrics for specific error kinds (ClientCreation, StreamConnect, StreamError,
                // StreamEnded) are already recorded in try_sync_once(). Only record
                // InitialSyncFailed for errors that weren't already categorized.
                if let Some(metrics) = metrics {
                    if let X509SourceError::ResourceLimitExceeded { kind, .. } = &e {
                        let metric_kind = match kind {
                            LimitKind::MaxSvids => MetricsErrorKind::LimitMaxSvids,
                            LimitKind::MaxBundles => MetricsErrorKind::LimitMaxBundles,
                            LimitKind::MaxBundleDerBytes => {
                                MetricsErrorKind::LimitMaxBundleDerBytes
                            }
                        };
                        metrics.record_error(metric_kind);
                    } else if matches!(&e, X509SourceError::NoSuitableSvid) {
                        // Only record InitialSyncFailed for NoSuitableSvid and other errors
                        // that weren't already categorized with specific metrics.
                        // Stream errors (ClientCreation, StreamConnect, StreamError, StreamEnded)
                        // are already recorded in try_sync_once().
                        metrics.record_error(MetricsErrorKind::InitialSyncFailed);
                    }
                }
                if sleep_or_cancel(cancel, backoff).await {
                    return Err(X509SourceError::Closed);
                }
                backoff = next_backoff(backoff, reconnect.max_backoff);
            }
        }
    }
}

async fn try_sync_once(
    make_client: &ClientFactory,
    picker: Option<&dyn SvidPicker>,
    limits: ResourceLimits,
    metrics: Option<&dyn MetricsRecorder>,
) -> Result<Arc<X509Context>, X509SourceError> {
    // Record ClientCreation error if client creation fails
    let client = match (make_client)().await {
        Ok(c) => c,
        Err(e) => {
            if let Some(m) = metrics {
                m.record_error(MetricsErrorKind::ClientCreation);
            }
            return Err(X509SourceError::Source(e));
        }
    };

    // Record StreamConnect error if stream connection fails
    let mut stream = match client.stream_x509_contexts().await {
        Ok(s) => s,
        Err(e) => {
            if let Some(m) = metrics {
                m.record_error(MetricsErrorKind::StreamConnect);
            }
            return Err(X509SourceError::Source(e));
        }
    };

    match stream.next().await {
        Some(Ok(ctx)) => {
            validate_limits(&ctx, limits)?;

            // Ensure it is usable with the picker/default selection before returning it.
            if let Some(p) = picker {
                p.pick_svid(ctx.svids())
                    .and_then(|idx| ctx.svids().get(idx))
                    .ok_or(X509SourceError::NoSuitableSvid)?;
            } else {
                ctx.default_svid().ok_or(X509SourceError::NoSuitableSvid)?;
            }

            Ok(Arc::new(ctx))
        }
        Some(Err(e)) => {
            // Record StreamError for stream read errors
            if let Some(m) = metrics {
                m.record_error(MetricsErrorKind::StreamError);
            }
            Err(X509SourceError::Source(e))
        }
        None => {
            // Record StreamEnded for empty stream
            if let Some(m) = metrics {
                m.record_error(MetricsErrorKind::StreamEnded);
            }
            Err(X509SourceError::StreamEnded)
        }
    }
}

async fn sleep_or_cancel(token: &CancellationToken, dur: Duration) -> bool {
    tokio::select! {
        () = token.cancelled() => true,
        () = sleep(dur) => false,
    }
}

/// Exponential backoff with full jitter (random delay between 0 and base).
///
/// Full jitter reduces synchronized reconnect storms across many workloads by
/// randomizing the delay. This is especially important in container fleets that
/// start simultaneously.
///
/// Note: Jitter is calculated in milliseconds, which may result in sub-millisecond
/// precision loss for very small durations. This is acceptable for backoff purposes.
#[allow(clippy::cast_possible_truncation)]
fn next_backoff(current: Duration, max: Duration) -> Duration {
    let doubled = current.saturating_mul(2);
    let base = if doubled > max { max } else { doubled };

    let base_ms_u128 = base.as_millis();
    if base_ms_u128 == 0 {
        return base;
    }

    let upper = base_ms_u128.min(u128::from(u64::MAX)) as u64;
    let jitter_ms = fastrand::u64(0..=upper);
    Duration::from_millis(jitter_ms)
}
