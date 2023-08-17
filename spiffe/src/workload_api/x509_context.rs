//! Defines a type that holds all the X.509 materials for a workload (i.e. X.509 SVIDs and bundles)

use crate::bundle::x509::X509BundleSet;
use crate::constants::DEFAULT_SVID;
use crate::svid::x509::X509Svid;

/// Represents all X.509 materials fetched from the Workload API.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct X509Context {
    svids: Vec<X509Svid>,
    bundle_set: X509BundleSet,
}

impl X509Context {
    /// Creates a new [`X509Context`].
    pub fn new(svids: Vec<X509Svid>, bundle_set: X509BundleSet) -> Self {
        Self { svids, bundle_set }
    }

    /// Returns the default [`X509Svid`], i.e. the first in the list.
    pub fn default_svid(&self) -> Option<&X509Svid> {
        self.svids.get(DEFAULT_SVID)
    }

    /// Returns the list of [`X509Svid`] in the context.
    pub fn svids(&self) -> &Vec<X509Svid> {
        &self.svids
    }

    /// Returns the [`X509BundleSet`] in the context.
    pub fn bundle_set(&self) -> &X509BundleSet {
        &self.bundle_set
    }
}
