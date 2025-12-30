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
//! use spiffe::bundle::BundleSource;
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

mod builder;
mod errors;
mod limits;
mod metrics;
mod source;
mod supervisor;

pub use builder::{ReconnectConfig, ResourceLimits, X509SourceBuilder};
pub use errors::{LimitKind, MetricsErrorKind, X509SourceError};
pub use metrics::MetricsRecorder;
pub use source::{SvidPicker, X509Source, X509SourceUpdates};
