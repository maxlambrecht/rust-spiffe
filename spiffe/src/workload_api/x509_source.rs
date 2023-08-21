//! # X509Source Module
//!
//! This module provides a source of X.509 SVIDs and X.509 bundles, backed by a workload API client
//! that continuously fetches the X.509 context (SVIDs and bundles) behind the scenes.
//! This ensures that the `X509Source` is always up to date.
//!
//! It allows for fetching and managing X.509 SVIDs and bundles, and includes functionality for updating
//! the context and closing the source. Users can utilize the `X509Source` to obtain SVIDs and bundles,
//! listen for updates, and manage the lifecycle of the source.
//!
//! ## Usage
//!
//! The `X509Source` can be created and configured to fetch SVIDs and bundles, respond to updates, and
//! handle closing. It provides a seamless interface for working with X.509 SVIDs and bundles.
//!
//! ### Example
//!
//! ```no_run
//! use spiffe::bundle::BundleSource;
//! use spiffe::spiffe_id::TrustDomain;
//! use spiffe::svid::SvidSource;
//! use spiffe::workload_api::x509_source::{X509Source, X509SourceError};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//! let source = X509Source::default().await?;
//! let svid = source.get_svid()?;
//! let trust_domain = TrustDomain::new("example.org").unwrap();
//! let bundle = source.get_bundle_for_trust_domain(&trust_domain)
//!     .map_err(|e| format!("Failed to get bundle for trust domain {}: {}", trust_domain, e))?;
//!
//! # Ok(())
//! # }
//! ```
//!
//! ## Error Handling
//!
//! The `X509SourceError` enum provides detailed error information, including errors related to GRPC client failures,
//! lock issues, and other non-specific errors.
//!
//! ## Update Handling
//!
//! The `X509Source` provides a method to listen for updates, allowing parts of your system to respond to changes.
//! The `updated` method returns a `watch::Receiver<()>` that can be used to listen for notifications when the `X509Source` is updated.
//!
//! ## Closing the Source
//!
//! The `close` method can be used to close the `X509Source`, canceling all spawned tasks and stopping updates.
use crate::bundle::x509::{X509Bundle, X509BundleSet};
use crate::bundle::BundleSource;
use crate::error::GrpcClientError;
use crate::spiffe_id::TrustDomain;
use crate::svid::x509::X509Svid;
use crate::svid::SvidSource;
use crate::workload_api::client::WorkloadApiClient;
use crate::workload_api::x509_context::X509Context;
use log::{debug, error, info};
use std::error::Error;
use std::sync::{Arc, PoisonError, RwLock};
use thiserror::Error;
use tokio::sync::watch;
use tokio_stream::StreamExt;
use tokio_util::sync::CancellationToken;

/// `SvidPicker` is a trait defining the behavior for selecting an `X509Svid`.
///
/// Implementors of this trait must provide a concrete implementation of the `pick_svid` method, which
/// takes a reference to a slice of `X509Svid` and returns an `Option<&X509Svid>`.
///
/// The trait requires that implementing types are both `Send` and `Sync`, ensuring that they can be
/// sent between threads and accessed concurrently.
///
/// # Example
///
/// ```
/// use spiffe::svid::x509::X509Svid;
/// use spiffe::workload_api::x509_source::SvidPicker;
/// struct SecondSvidPicker;
///
/// impl SvidPicker for SecondSvidPicker {
///     fn pick_svid<'a>(&self, svids: &'a [X509Svid]) -> Option<&'a X509Svid> {
///         svids.get(1)  // return second svid
///     }
/// }
/// ```
pub trait SvidPicker: Send + Sync {
    /// Selects an `X509Svid` from the provided slice of `X509Svid`.
    ///
    /// # Parameters
    /// * `svids`: A reference to a slice of `X509Svid` from which the `X509Svid` should be selected.
    ///
    /// # Returns
    /// * An `Option<&X509Svid>`, where a `None` value indicates that no suitable `X509Svid` was found.
    fn pick_svid<'a>(&self, svids: &'a [X509Svid]) -> Option<&'a X509Svid>;
}

/// Enumerates errors that can occur within the X509Source.
#[derive(Debug, Error)]
pub enum X509SourceError {
    /// Error when a GRPC client fails to fetch an X509Context.
    #[error("GRPC client error: {0}")]
    GrpcError(GrpcClientError),

    /// Error when no suitable SVID is found by the picker.
    #[error("No suitable SVID found by picker")]
    NoSuitableSvid,

    /// Error when a lock gets poisoned.
    #[error("Lock poisoned: {0}")]
    LockPoisoned(String),

    /// Error when failing to acquire a write lock.
    #[error("Failed to acquire write lock for {0}: {1}")]
    WriteLockAcquisitionFailed(String, String),

    /// Other non-specific error.
    #[error("{0}")]
    Other(String),
}

impl X509SourceError {
    fn from_lock_err<T>(err: PoisonError<T>) -> Self {
        X509SourceError::LockPoisoned(err.to_string())
    }
}

/// Represents a source of X.509 SVIDs and X.509 bundles.
///
///
/// `X509Source` implements the [`BundleSource`] and [`SvidSource`] traits.
///
/// The methods return cloned instances of the underlying objects.
#[allow(missing_debug_implementations)]
pub struct X509Source {
    svid: RwLock<Option<X509Svid>>,
    bundles: RwLock<Option<X509BundleSet>>,
    svid_picker: Option<Box<dyn SvidPicker>>,
    workload_api_client: WorkloadApiClient,
    closed: RwLock<bool>,
    cancellation_token: CancellationToken,
    update_notifier: watch::Sender<()>,
    updated: watch::Receiver<()>,
}

/// Builder for `X509Source`.
#[allow(missing_debug_implementations)]
pub struct X509SourceBuilder {
    client: Option<WorkloadApiClient>,
    svid_picker: Option<Box<dyn SvidPicker>>,
}

/// A builder for creating a new `X509Source` with optional client and svid_picker configurations.
///
/// Allows for customization by accepting a client and/or svid_picker.
///
/// # Example
///
/// ```no_run
/// use std::error::Error;
/// use spiffe::workload_api::client::WorkloadApiClient;
/// use spiffe::workload_api::x509_source::X509SourceBuilder;
/// use spiffe::svid::x509::X509Svid;
/// use spiffe::workload_api::x509_source::SvidPicker;
///
/// struct SecondSvidPicker;
///
/// impl SvidPicker for SecondSvidPicker {
///     fn pick_svid<'a>(&self, svids: &'a [X509Svid]) -> Option<&'a X509Svid> {
///         svids.get(1)  // return second svid
///     }
/// }
///
/// # async fn example() -> Result<(), Box< dyn Error>> {
/// let client = WorkloadApiClient::default().await?;
/// let source = X509SourceBuilder::new()
///    .with_client(client)
///    .with_picker(Box::new(SecondSvidPicker))
///    .build()
///    .await?;
///
/// # Ok(())
/// # }
/// ```
///
/// # Returns
/// A `Result` containing an `Arc<X509Source>` or an `X509SourceError` if an error occurs.
impl X509SourceBuilder {
    /// Creates a new `X509SourceBuilder`.
    pub fn new() -> Self {
        Self {
            client: None,
            svid_picker: None,
        }
    }

    /// Sets the Workload API client to be used by the X509Source.
    pub fn with_client(mut self, client: WorkloadApiClient) -> Self {
        self.client = Some(client);
        self
    }

    /// Sets the svid_picker to be used by the X509Source.
    pub fn with_picker(mut self, svid_picker: Box<dyn SvidPicker>) -> Self {
        self.svid_picker = Some(svid_picker);
        self
    }

    /// Builds an `X509Source` using the provided configuration.
    pub async fn build(self) -> Result<Arc<X509Source>, X509SourceError> {
        let client = match self.client {
            Some(client) => client,
            None => WorkloadApiClient::default()
                .await
                .map_err(|e| X509SourceError::GrpcError(e))?,
        };

        X509Source::new(client, self.svid_picker).await
    }
}

impl SvidSource for X509Source {
    type Item = X509Svid;

    /// Retrieves the X.509 SVID from the source.
    ///
    /// # Returns
    ///
    /// An `Result<Option<X509Svid>, Box<dyn Error + Send + Sync + 'static>>` containing the X.509 SVID if available.
    /// Returns `Ok(None)` if no SVID is found.
    /// Returns an error if the source is closed or if there's an issue fetching the SVID.
    fn get_svid(&self) -> Result<Option<Self::Item>, Box<dyn Error + Send + Sync + 'static>> {
        self.assert_not_closed().map_err(Box::new)?;

        let svid_option = self.svid.read().map_err(|e| {
            Box::new(X509SourceError::LockPoisoned(e.to_string()))
                as Box<dyn Error + Send + Sync + 'static>
        })?;

        Ok(svid_option.clone())
    }
}

impl BundleSource for X509Source {
    type Item = X509Bundle;

    /// Retrieves the X.509 bundle for the given trust domain.
    ///
    /// # Arguments
    /// * `trust_domain` - The trust domain for which the X.509 bundle is to be retrieved.
    ///
    /// # Returns
    /// A `Result` containing an `Option<X509Bundle>` for the given trust domain. If the bundle is not found, returns `Ok(None)`.
    ///
    /// # Errors
    /// Returns a boxed error if the source is closed or if there is an issue accessing the bundle.
    fn get_bundle_for_trust_domain(
        &self,
        trust_domain: &TrustDomain,
    ) -> Result<Option<Self::Item>, Box<dyn Error + Send + Sync + 'static>> {
        self.assert_not_closed().map_err(Box::new)?;

        // Read the bundles
        let bundles_option = self
            .bundles
            .read()
            .map_err(|e| Box::new(X509SourceError::from_lock_err(e)))?;
        let bundle_set = match bundles_option.as_ref() {
            Some(set) => set,
            None => return Ok(None),
        };

        // Get the bundle for the trust domain
        let bundle = bundle_set.get_bundle(trust_domain);

        // Return the bundle if found, or Ok(None) if not found
        Ok(bundle.cloned())
    }
}

// public methods
impl X509Source {
    /// Builds a new `X509Source` using a default [`WorkloadApiClient`] and no SVID picker.
    /// Since no SVID picker is provided, the `get_svid` method will return the default SVID.
    ///
    /// This method is asynchronous and may return an error if the initialization fails.
    pub async fn default() -> Result<Arc<Self>, X509SourceError> {
        X509SourceBuilder::new().build().await
    }

    /// Returns a `watch::Receiver<()>` that can be used to listen for notifications when the X509Source is updated.
    ///
    /// # Example
    ///
    /// ``no_run
    /// let mut update_channel = source.updated(); // Get the watch receiver for the source
    ///
    /// // Asynchronously handle updates in a loop
    /// tokio::spawn(async move {
    ///     loop {
    ///         match update_channel.changed().await {
    ///             Ok(_) => {
    ///                 println!("X509Source was updated!");
    ///             },
    ///             Err(_) => {
    ///                 println!("Watch channel closed; exiting update loop");
    ///                 break;
    ///             }
    ///         }
    ///     }
    /// });
    /// ```
    pub fn updated(&self) -> watch::Receiver<()> {
        self.updated.clone()
    }

    /// Closes the X509Source cancelling all spawned tasks.
    pub fn close(&self) -> Result<(), X509SourceError> {
        self.assert_not_closed()?;

        let mut closed = self
            .closed
            .write()
            .map_err(X509SourceError::from_lock_err)?;
        *closed = true;

        self.cancellation_token.cancel();

        info!("X509Source has been closed.");
        Ok(())
    }
}

// private methods
impl X509Source {
    async fn new(
        client: WorkloadApiClient,
        svid_picker: Option<Box<dyn SvidPicker>>,
    ) -> Result<Arc<X509Source>, X509SourceError> {
        let (update_notifier, updated) = watch::channel(());
        let cancellation_token = CancellationToken::new();
        let cancellation_token_clone = cancellation_token.clone();

        let source = Arc::new(X509Source {
            svid: RwLock::new(None),
            bundles: RwLock::new(None),
            workload_api_client: client,
            closed: RwLock::new(false),
            svid_picker,
            cancellation_token,
            updated,
            update_notifier,
        });

        let source_clone = Arc::clone(&source);
        let mut client_clone = source_clone.workload_api_client.clone();
        let mut stream = client_clone
            .stream_x509_contexts()
            .await
            .map_err(|e| X509SourceError::GrpcError(GrpcClientError::from(e)))?;

        // Block until the first X509Context is fetched.
        if let Some(update) = stream.next().await {
            match update {
                Ok(x509_context) => source_clone.set_x509_context(x509_context).map_err(|e| {
                    X509SourceError::Other(format!("Failed to set X509Context: {}", e))
                })?,
                Err(e) => return Err(X509SourceError::GrpcError(GrpcClientError::from(e))),
            }
        } else {
            return Err(X509SourceError::Other(
                "Stream ended without an update".to_string(),
            ));
        }

        // Spawn a task to handle subsequent updates
        tokio::spawn(async move {
            loop {
                if cancellation_token_clone.is_cancelled() {
                    debug!("Cancellation signal received; stopping updates.");
                    break;
                }

                match stream.next().await {
                    Some(update) => match update {
                        Ok(x509_context) => {
                            if let Err(e) = source_clone.set_x509_context(x509_context) {
                                error!("Error updating X509 context: {}", e);
                            } else {
                                info!("X509 context updated successfully.");
                            }
                        }
                        Err(e) => error!("GRPC client error: {}", e),
                    },
                    None => {
                        error!("Stream ended; no more updates will be received.");
                        break;
                    }
                }
            }
        });

        Ok(source)
    }

    fn set_x509_context(&self, x509_context: X509Context) -> Result<(), X509SourceError> {
        let svid = if let Some(ref svid_picker) = self.svid_picker {
            svid_picker
                .pick_svid(&x509_context.svids())
                .ok_or(X509SourceError::NoSuitableSvid)?
        } else {
            x509_context
                .default_svid()
                .ok_or(X509SourceError::NoSuitableSvid)?
        };

        self.set_svid(&svid)?;

        self.bundles
            .write()
            .map_err(|e| {
                X509SourceError::WriteLockAcquisitionFailed("bundles".to_string(), e.to_string())
            })?
            .replace(x509_context.bundle_set().clone());

        self.notify_update();
        Ok(())
    }

    fn set_svid(&self, svid: &X509Svid) -> Result<(), X509SourceError> {
        self.svid
            .write()
            .map_err(|e| {
                X509SourceError::WriteLockAcquisitionFailed("svids".to_string(), e.to_string())
            })?
            .replace(svid.clone());
        Ok(())
    }

    fn notify_update(&self) {
        let _ = self.update_notifier.send(());
    }

    fn assert_not_closed(&self) -> Result<(), X509SourceError> {
        let closed = self.closed.read().map_err(X509SourceError::from_lock_err)?;
        if *closed {
            return Err(X509SourceError::Other("X509Source is closed".into()));
        }
        Ok(())
    }
}
