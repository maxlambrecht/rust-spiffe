//! Defines a type that holds all the X.509 materials for a workload (i.e. X.509 SVIDs and bundles)

use crate::constants::DEFAULT_SVID;
use crate::{X509BundleSet, X509Svid};
use std::sync::Arc;

/// Represents all X.509 materials fetched from the Workload API.
///
/// An `X509Context` contains the set of X.509 SVIDs issued to the workload
/// along with the corresponding trust bundles.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct X509Context {
    svids: Vec<Arc<X509Svid>>,
    bundle_set: Arc<X509BundleSet>,
}

impl X509Context {
    /// Creates a new [`X509Context`].
    ///
    /// The provided SVIDs are collected and stored internally.
    /// The bundle set is shared internally via `Arc`.
    #[must_use]
    pub fn new(
        svids: impl IntoIterator<Item = Arc<X509Svid>>,
        bundle_set: impl Into<Arc<X509BundleSet>>,
    ) -> Self {
        Self {
            svids: svids.into_iter().collect(),
            bundle_set: bundle_set.into(),
        }
    }

    /// Returns the default [`X509Svid`], if present.
    ///
    /// The default SVID is the first SVID returned by the Workload API.
    pub fn default_svid(&self) -> Option<&Arc<X509Svid>> {
        self.svids.get(DEFAULT_SVID)
    }

    /// Returns all X.509 SVIDs in this context.
    pub fn svids(&self) -> &[Arc<X509Svid>] {
        self.svids.as_slice()
    }

    /// Returns the set of X.509 bundles associated with this context.
    pub fn bundle_set(&self) -> &Arc<X509BundleSet> {
        &self.bundle_set
    }
}
