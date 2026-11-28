//! X.509 Source: high-level watcher/caching abstraction.
//!
//! Provides the [`X509Source`] type and related configuration types
//! for automatic SVID/bundle watching and caching.
//!
//! Available with the `x509-source` feature.
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
//! Permission denial (`PermissionDenied` or `NoIdentityIssued`) on the monitored RPC
//! withdraws its SVIDs and bundles until a valid complete response reauthorizes it.
//! Temporary transport failures and malformed/over-limit updates retain accepted permission.
//! Complete responses replace trust even when the picker selects nothing or its SVID is
//! expired. The picker never falls back. Use [`X509Source::state`] for a coherent revision,
//! context, selected identity, withdrawal reason, and terminal status. Source getters reject
//! terminal closure; the final observation lets integrations choose a terminal policy.
//!
//! Primary types are re-exported at the crate root. For advanced configuration types
//! (e.g., `LimitKind`, `MetricsErrorKind`, `MetricsRecorder`), import from this module.
//!
//! # Startup
//!
//! Construction waits for an accepted X.509 context with a selected, unexpired SVID, so
//! a ready source implies an identity. By default it waits indefinitely, including for
//! an unregistered workload. [`X509SourceBuilder::initial_sync_timeout`] bounds it; on
//! expiry [`X509SourceError::InitialSyncTimeout`] carries the most recent recoverable
//! failure, as a diagnostic. The timeout does not change which failures are retried.
//!
//! An application can apply its own policy over repeated bounded attempts. Here it
//! gives up after several windows that ended with the workload still unregistered:
//!
//! ```no_run
//! # #[cfg(feature = "x509-source")]
//! # async fn example() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//! use spiffe::{WorkloadApiError, X509Source, X509SourceError};
//! use std::time::Duration;
//!
//! const MAX_UNREGISTERED_WINDOWS: u32 = 10;
//! let mut unregistered_windows = 0;
//! let source = loop {
//!     // `build()` consumes the builder, so create one per attempt.
//!     let result = X509Source::builder()
//!         .initial_sync_timeout(Duration::from_secs(30))
//!         .build()
//!         .await;
//!     match result {
//!         Ok(source) => break source,
//!         Err(X509SourceError::InitialSyncTimeout { last_error, .. }) => {
//!             // The last failure seen in this window, not necessarily what the
//!             // pending attempt was waiting on. `None`: the first attempt was pending.
//!             let unregistered = matches!(
//!                 last_error.as_deref(),
//!                 Some(X509SourceError::Source(WorkloadApiError::NoIdentityIssued))
//!             );
//!             unregistered_windows = if unregistered { unregistered_windows + 1 } else { 0 };
//!             if unregistered_windows >= MAX_UNREGISTERED_WINDOWS {
//!                 return Err("workload has no registration entry".into());
//!             }
//!         }
//!         // Every other error is already terminal, such as invalid endpoint
//!         // configuration or an unsupported FetchX509SVID.
//!         Err(error) => return Err(error.into()),
//!     }
//! };
//! # drop(source);
//! # Ok(())
//! # }
//! ```
//!
//! See the crate's Workload API startup policy for cancellation, probes and Kubernetes.
//!
//! # Example
//!
//! ```no_run
//! # #[cfg(feature = "x509-source")]
//! # async fn example() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//! use spiffe::{TrustDomain, X509Source};
//! use spiffe::BundleSource;
//!
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

mod builder;
mod errors;
mod limits;
mod metrics;
mod source;
mod supervisor;
mod types;

pub use builder::{ReconnectConfig, ResourceLimits, X509SourceBuilder};
pub use errors::{LimitKind, MetricsErrorKind, X509SourceError};
pub use metrics::MetricsRecorder;
pub use source::{X509Source, X509SourceState, X509SourceUpdates};
pub use types::SvidPicker;
