//! Trust domain policy for federation control.
//!
//! This module provides [`TrustDomainPolicy`], which allows you to restrict which
//! trust domains from the bundle set are actually used during certificate verification.
//!
//! # Examples
//!
//! ```rust
//! use spiffe_rustls::{AllowList, AnyInBundleSet, LocalOnly, TrustDomainPolicy};
//! use std::collections::BTreeSet;
//!
//! // Default: use all bundles from the Workload API (using re-exported variant)
//! let policy = AnyInBundleSet;
//!
//! // Restrict to specific trust domains (using re-exported variant)
//! let mut allowed = BTreeSet::new();
//! allowed.insert("broker.example".try_into().unwrap());
//! allowed.insert("stockmarket.example".try_into().unwrap());
//! let policy = AllowList(allowed);
//!
//! // Only trust a single trust domain (using re-exported variant)
//! let policy = LocalOnly("example.org".try_into().unwrap());
//!
//! // You can also use the full path if preferred
//! let policy = TrustDomainPolicy::AnyInBundleSet;
//! ```

use spiffe::TrustDomain;
use std::collections::BTreeSet;

/// Policy for selecting which trust domains to trust during certificate verification.
///
/// When SPIFFE federation is configured, the Workload API delivers trust bundles
/// for multiple trust domains. This policy allows you to restrict which of those
/// bundles are actually used during certificate verification.
///
/// This is a **defense-in-depth** mechanism. The primary trust model comes from
/// the bundle set delivered by the SPIFFE Workload API. This policy provides an
/// additional layer of control over which trust domains are accepted.
///
/// **Default**: `AnyInBundleSet` - use all bundles provided by the Workload API.
///
/// # Examples
///
/// ```rust
/// use spiffe_rustls::{AllowList, AnyInBundleSet, TrustDomainPolicy};
/// use std::collections::BTreeSet;
///
/// // Default: trust any domain in the bundle set
/// let policy = AnyInBundleSet;
///
/// // Restrict to specific trust domains (using re-exported variant)
/// let mut allowed = BTreeSet::new();
/// allowed.insert("broker.example".try_into().unwrap());
/// let policy = AllowList(allowed);
///
/// // You can also use the full path if preferred
/// let policy = TrustDomainPolicy::default();
/// ```
#[derive(Debug, Clone, Default)]
pub enum TrustDomainPolicy {
    /// Default: use all trust domain bundles provided by the Workload API.
    ///
    /// When SPIFFE federation is configured, the Workload API delivers bundles
    /// for multiple trust domains. This policy accepts all of them, allowing
    /// the verifier to automatically select the correct bundle based on the
    /// peer's SPIFFE ID. No additional configuration is needed for federation
    /// to work.
    #[default]
    AnyInBundleSet,

    /// Restrict to these trust domains only.
    ///
    /// Only bundles for these trust domains will be used, even if other bundles
    /// are present in the bundle set.
    AllowList(BTreeSet<TrustDomain>),

    /// Only trust the specified trust domain.
    ///
    /// Only bundles for this trust domain will be used, even if the Workload API
    /// provides bundles for other trust domains. This restricts certificate
    /// verification to a single trust domain.
    LocalOnly(TrustDomain),
}

impl TrustDomainPolicy {
    /// Checks if a trust domain is allowed by this policy.
    pub fn allows(&self, trust_domain: &TrustDomain) -> bool {
        match self {
            Self::AnyInBundleSet => true,
            Self::AllowList(allowed) => allowed.contains(trust_domain),
            Self::LocalOnly(local) => trust_domain == local,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_any_in_bundle_set() {
        let policy = TrustDomainPolicy::AnyInBundleSet;
        let td1 = TrustDomain::new("example.org").unwrap();
        let td2 = TrustDomain::new("other.org").unwrap();

        assert!(policy.allows(&td1));
        assert!(policy.allows(&td2));
    }

    #[test]
    fn test_allow_list() {
        let td1 = TrustDomain::new("example.org").unwrap();
        let td2 = TrustDomain::new("other.org").unwrap();
        let td3 = TrustDomain::new("third.org").unwrap();

        let mut allowed = BTreeSet::new();
        allowed.insert(td1.clone());
        allowed.insert(td2.clone());

        let policy = TrustDomainPolicy::AllowList(allowed);
        assert!(policy.allows(&td1));
        assert!(policy.allows(&td2));
        assert!(!policy.allows(&td3));
    }

    #[test]
    fn test_local_only() {
        let local = TrustDomain::new("example.org").unwrap();
        let other = TrustDomain::new("other.org").unwrap();

        let policy = TrustDomainPolicy::LocalOnly(local.clone());
        assert!(policy.allows(&local));
        assert!(!policy.allows(&other));
    }
}
