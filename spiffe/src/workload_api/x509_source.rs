//! Live X.509 SVID and bundle source backed by the SPIFFE Workload API.
//!
//! `X509Source` performs an initial sync before becoming usable, then watches the Workload API
//! for rotations. Transient failures are handled by reconnecting with exponential backoff.
//!
//! Use [`X509Source::updated`] to subscribe to change notifications, and [`X509Source::shutdown`]
//! to stop background tasks.
//!
//! # Example
//!
//! ```no_run
//! use spiffe::{BundleSource, TrustDomain, X509Source};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//! let source = X509Source::new().await?;
//!
//! let svid = source.svid()?;
//! let td = TrustDomain::new("example.org")?;
//! let bundle = source
//!     .get_bundle_for_trust_domain(&td)?
//!     .ok_or("missing bundle")?;
//!
//! # Ok(())
//! # }
//! ```
use crate::error::GrpcClientError;
use crate::{
    BundleSource, SvidSource, TrustDomain, WorkloadApiClient, X509Bundle, X509BundleSet,
    X509Context, X509Svid,
};
use arc_swap::ArcSwap;
use log::{debug, error, info, warn};
use std::error::Error as StdError;
use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use thiserror::Error;
use tokio::sync::{Mutex, watch};
use tokio::task::JoinHandle;
use tokio::time::{Duration, sleep};
use tokio_stream::StreamExt;
use tokio_util::sync::CancellationToken;

type ClientFuture =
    Pin<Box<dyn Future<Output = Result<WorkloadApiClient, GrpcClientError>> + Send + 'static>>;

type ClientFactory = Arc<dyn Fn() -> ClientFuture + Send + Sync + 'static>;

/// Strategy for selecting an X.509 SVID when multiple SVIDs are available.
pub trait SvidPicker: Debug + Send + Sync {
    /// Selects an SVID from the provided slice.
    ///
    /// Returning `None` indicates that no suitable SVID could be selected.
    fn pick_svid<'a>(&self, svids: &'a [X509Svid]) -> Option<&'a X509Svid>;
}

/// Reconnect/backoff configuration.
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

/// Errors returned by `X509Source`.
#[derive(Debug, Error)]
pub enum X509SourceError {
    /// Workload API client error.
    #[error("grpc client error: {0}")]
    Grpc(#[from] GrpcClientError),

    /// No SVID could be selected from the received context.
    #[error("no suitable svid found")]
    NoSuitableSvid,

    /// The source was closed.
    #[error("source is closed")]
    Closed,

    /// The workload API stream ended.
    #[error("workload api stream ended")]
    StreamEnded,
}

/// Live source of X.509 SVIDs and bundles from the SPIFFE Workload API.
///
/// `X509Source` performs an initial sync before returning from [`X509Source::new`].
/// Updates are applied atomically and can be observed via [`X509Source::updated`].
pub struct X509Source {
    svid: ArcSwap<X509Svid>,
    bundles: ArcSwap<X509BundleSet>,

    svid_picker: Option<Box<dyn SvidPicker>>,
    reconnect: ReconnectConfig,
    make_client: ClientFactory,

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
            .field("svid", &"<ArcSwap<X509Svid>>")
            .field("bundles", &"<ArcSwap<X509BundleSet>>")
            .field(
                "svid_picker",
                &self.svid_picker.as_ref().map(|_| "<SvidPicker>"),
            )
            .field("reconnect", &self.reconnect)
            .field("make_client", &"<ClientFactory>")
            .field("closed", &self.closed.load(Ordering::Relaxed))
            .field("cancel", &self.cancel)
            .field("update_seq", &self.update_seq)
            .field("update_tx", &"<watch::Sender<u64>>")
            .field("update_rx", &"<watch::Receiver<u64>>")
            .finish()
    }
}

/// Builder for [`X509Source`].
///
/// Use this when you need explicit configuration (socket path, picker, backoff).
pub struct X509SourceBuilder {
    svid_picker: Option<Box<dyn SvidPicker>>,
    reconnect: ReconnectConfig,
    make_client: Option<ClientFactory>,
}

impl Debug for X509SourceBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X509SourceBuilder")
            .field(
                "svid_picker",
                &self.svid_picker.as_ref().map(|_| "<SvidPicker>"),
            )
            .field("reconnect", &self.reconnect)
            .field(
                "make_client",
                &self.make_client.as_ref().map(|_| "<ClientFactory>"),
            )
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
    pub fn new() -> Self {
        Self {
            svid_picker: None,
            reconnect: ReconnectConfig::default(),
            make_client: None,
        }
    }

    /// Sets the Workload API socket path.
    ///
    /// Accepts either a filesystem path (e.g. `/tmp/spire-agent/public/api.sock`)
    /// or a full URI (e.g. `unix:///tmp/spire-agent/public/api.sock`).
    pub fn with_socket_path(mut self, socket_path: impl Into<Arc<str>>) -> Self {
        let socket_path = socket_path.into();

        let factory: ClientFactory = Arc::new(move || {
            let socket_path = socket_path.clone();
            Box::pin(async move { WorkloadApiClient::new_from_path(socket_path).await })
        });

        self.make_client = Some(factory);
        self
    }

    /// Sets a custom client factory.
    pub fn with_client_factory(mut self, factory: ClientFactory) -> Self {
        self.make_client = Some(factory);
        self
    }

    /// Sets a custom SVID selection strategy.
    pub fn with_picker(mut self, svid_picker: Box<dyn SvidPicker>) -> Self {
        self.svid_picker = Some(svid_picker);
        self
    }

    /// Sets the reconnect backoff range.
    pub fn with_reconnect_backoff(mut self, min_backoff: Duration, max_backoff: Duration) -> Self {
        self.reconnect = ReconnectConfig {
            min_backoff,
            max_backoff,
        };
        self
    }

    /// Builds a ready-to-use [`X509Source`].
    pub async fn build(self) -> Result<Arc<X509Source>, X509SourceError> {
        let make_client = self
            .make_client
            .unwrap_or_else(|| Arc::new(|| Box::pin(async { WorkloadApiClient::default().await })));

        X509Source::new_with(make_client, self.svid_picker, self.reconnect).await
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
    pub async fn new() -> Result<Arc<Self>, X509SourceError> {
        X509SourceBuilder::new().build().await
    }

    /// Cancels background tasks and waits for termination.
    pub async fn shutdown(&self) -> Result<(), X509SourceError> {
        if self.closed.swap(true, Ordering::AcqRel) {
            return Err(X509SourceError::Closed);
        }
        self.cancel.cancel();

        if let Some(handle) = self.supervisor.lock().await.take() {
            let _ = handle.await;
        }

        Ok(())
    }

    /// Returns a receiver that is notified on each successful update.
    ///
    /// The received value is a monotonically increasing counter.
    pub fn updated(&self) -> watch::Receiver<u64> {
        self.update_rx.clone()
    }

    /// Returns the current X.509 SVID.
    pub fn svid(&self) -> Result<X509Svid, X509SourceError> {
        self.assert_open()?;
        Ok((**self.svid.load()).clone())
    }
}

impl Drop for X509Source {
    fn drop(&mut self) {
        // best-effort cancellation
        self.cancel.cancel();
    }
}

impl SvidSource for X509Source {
    type Item = X509Svid;

    fn get_svid(&self) -> Result<Option<Self::Item>, Box<dyn StdError + Send + Sync + 'static>> {
        self.assert_open().map_err(Box::new)?;
        Ok(Some((**self.svid.load()).clone()))
    }
}

impl BundleSource for X509Source {
    type Item = X509Bundle;

    fn get_bundle_for_trust_domain(
        &self,
        trust_domain: &TrustDomain,
    ) -> Result<Option<Self::Item>, Box<dyn StdError + Send + Sync + 'static>> {
        self.assert_open().map_err(Box::new)?;
        Ok(self.bundles.load().get_bundle(trust_domain).cloned())
    }
}

// private/internal
impl X509Source {
    async fn new_with(
        make_client: ClientFactory,
        svid_picker: Option<Box<dyn SvidPicker>>,
        reconnect: ReconnectConfig,
    ) -> Result<Arc<X509Source>, X509SourceError> {
        let (update_tx, update_rx) = watch::channel(0u64);
        let cancel = CancellationToken::new();

        let (initial_svid, initial_bundles) =
            initial_sync_with_retry(&make_client, svid_picker.as_deref(), &cancel, reconnect)
                .await?;

        let src = Arc::new(Self {
            svid: ArcSwap::from_pointee(initial_svid),
            bundles: ArcSwap::from_pointee(initial_bundles),
            svid_picker,
            reconnect,
            make_client,
            closed: AtomicBool::new(false),
            cancel,
            update_seq: AtomicU64::new(0),
            update_tx,
            update_rx,
            supervisor: Mutex::new(None),
        });

        let cloned = Arc::clone(&src);
        let token = cloned.cancel.clone();
        let handle = tokio::spawn(async move { cloned.run_update_supervisor(token).await });
        *src.supervisor.lock().await = Some(handle);

        Ok(src)
    }

    fn assert_open(&self) -> Result<(), X509SourceError> {
        if self.closed.load(Ordering::Acquire) || self.cancel.is_cancelled() {
            return Err(X509SourceError::Closed);
        }
        Ok(())
    }

    fn notify_update(&self) {
        let next = self.update_seq.fetch_add(1, Ordering::Relaxed) + 1;
        let _ = self.update_tx.send(next);
    }

    fn set_x509_context(&self, x509_context: X509Context) -> Result<(), X509SourceError> {
        let picked = if let Some(ref picker) = self.svid_picker {
            picker
                .pick_svid(x509_context.svids())
                .ok_or(X509SourceError::NoSuitableSvid)?
        } else {
            x509_context
                .default_svid()
                .ok_or(X509SourceError::NoSuitableSvid)?
        };

        self.svid.store(Arc::new(picked.clone()));
        self.bundles
            .store(Arc::new(x509_context.bundle_set().clone()));

        self.notify_update();
        Ok(())
    }

    async fn run_update_supervisor(&self, cancellation_token: CancellationToken) {
        let mut backoff = self.reconnect.min_backoff;

        loop {
            if cancellation_token.is_cancelled() {
                debug!("Cancellation signal received; stopping updates.");
                return;
            }

            let mut client = match (self.make_client)().await {
                Ok(c) => {
                    backoff = self.reconnect.min_backoff;
                    c
                }
                Err(e) => {
                    warn!("Failed to create WorkloadApiClient: {e}. Retrying in {backoff:?}.");
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
                    Some(Ok(ctx)) => match self.set_x509_context(ctx) {
                        Err(e) => {
                            error!("Error updating X509 context: {e}");
                        }
                        _ => {
                            debug!("X509 context updated.");
                        }
                    },
                    Some(Err(e)) => {
                        warn!("Workload API stream error: {e}. Reconnecting...");
                        break;
                    }
                    None => {
                        warn!("Workload API stream ended. Reconnecting...");
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

async fn initial_sync_with_retry(
    make_client: &ClientFactory,
    picker: Option<&dyn SvidPicker>,
    cancel: &CancellationToken,
    reconnect: ReconnectConfig,
) -> Result<(X509Svid, X509BundleSet), X509SourceError> {
    let mut backoff = reconnect.min_backoff;

    loop {
        if cancel.is_cancelled() {
            return Err(X509SourceError::Closed);
        }

        match try_sync_once(make_client, picker).await {
            Ok(v) => return Ok(v),
            Err(e) => {
                warn!("Initial sync failed: {e}. Retrying in {backoff:?}.");
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
) -> Result<(X509Svid, X509BundleSet), X509SourceError> {
    let mut client = (make_client)().await.map_err(X509SourceError::Grpc)?;
    let mut stream = client
        .stream_x509_contexts()
        .await
        .map_err(X509SourceError::Grpc)?;

    match stream.next().await {
        Some(Ok(ctx)) => {
            let picked = if let Some(p) = picker {
                p.pick_svid(ctx.svids())
                    .ok_or(X509SourceError::NoSuitableSvid)?
            } else {
                ctx.default_svid().ok_or(X509SourceError::NoSuitableSvid)?
            };
            Ok((picked.clone(), ctx.bundle_set().clone()))
        }
        Some(Err(e)) => Err(X509SourceError::Grpc(e)),
        None => Err(X509SourceError::StreamEnded),
    }
}

async fn sleep_or_cancel(token: &CancellationToken, dur: Duration) -> bool {
    tokio::select! {
        _ = token.cancelled() => true,
        _ = sleep(dur) => false,
    }
}

fn next_backoff(current: Duration, max: Duration) -> Duration {
    let doubled = current.saturating_mul(2);
    if doubled > max { max } else { doubled }
}
