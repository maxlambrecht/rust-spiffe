//! JWT Source: high-level watcher/caching abstraction for JWT bundles.
//!
//! Provides the [`JwtSource`] type and related configuration types
//! for automatic JWT bundle watching and caching, plus on-demand JWT SVID fetching.
//!
//! Available with the `jwt-source` feature.
//!
//! `JwtSource` performs an initial synchronization before becoming usable, then watches the
//! Workload API for bundle rotations. Transient failures are handled by reconnecting with backoff.
//!
//! Unlike X.509 SVIDs which are streamed continuously, JWT SVIDs are fetched on-demand with
//! specific audiences. Use [`JwtSource::fetch_jwt_svid`] to fetch JWT SVIDs as needed.
//!
//! Use [`JwtSource::updated`] to subscribe to bundle change notifications, and [`JwtSource::shutdown`]
//! to stop background tasks.
//!
//! Permission denial on the monitored bundle RPC withdraws bundles until a valid complete
//! bundle response reauthorizes it. Temporary transport failures and rejected updates retain
//! accepted permission. Denial of an independent JWT issuance request only fails that request;
//! successful issuance cannot reauthorize the bundle stream. [`JwtSource::state`] exposes the
//! coherent revision, permission, bundle material, and terminal status.
//!
//! # Startup
//!
//! Construction waits for an accepted JWT bundle set, so a ready source implies trust
//! bundles only, not that a JWT-SVID can be issued to this workload: JWT-SVIDs are
//! requested separately, on demand. For example, a SPIRE agent with
//! `allow_unauthenticated_verifiers` enabled serves bundles to unregistered workloads.
//! Applications that issue JWT-SVIDs should fetch one at startup:
//!
//! ```no_run
//! # #[cfg(feature = "jwt-source")]
//! # async fn example() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//! use spiffe::{JwtSource, JwtSourceError};
//! use std::time::Duration;
//!
//! let source = match JwtSource::builder()
//!     .initial_sync_timeout(Duration::from_secs(30))
//!     .build()
//!     .await
//! {
//!     Ok(source) => source,
//!     Err(JwtSourceError::InitialSyncTimeout { last_error, .. }) => {
//!         return Err(format!("JWT bundles unavailable; last error: {last_error:?}").into());
//!     }
//!     Err(error) => return Err(error.into()),
//! };
//! // Bundles are ready; confirm that this workload can also be issued a JWT-SVID.
//! let _svid = source.fetch_jwt_svid(["startup-check"]).await?;
//! # Ok(())
//! # }
//! ```
//!
//! [`JwtSourceBuilder::initial_sync_timeout`] bounds construction; on expiry the error
//! carries the most recent recoverable failure as a diagnostic, without changing which
//! failures are retried.
//!
//! Primary types are re-exported at the crate root. For advanced configuration types
//! (e.g., `LimitKind`, `MetricsErrorKind`, `MetricsRecorder`), import from this module.
//!
//! # Example
//!
//! ```no_run
//! # #[cfg(feature = "jwt-source")]
//! # async fn example() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//! use spiffe::{TrustDomain, JwtSource};
//! use spiffe::BundleSource;
//!
//! let source = JwtSource::new().await?;
//!
//! // Fetch a JWT SVID for a specific audience
//! let jwt_svid = source.fetch_jwt_svid(&["service-a", "service-b"]).await?;
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

pub use builder::{JwtSourceBuilder, ReconnectConfig, ResourceLimits};
pub use errors::{JwtSourceError, LimitKind, MetricsErrorKind};
pub use metrics::MetricsRecorder;
pub use source::{JwtSource, JwtSourceState, JwtSourceUpdates};
