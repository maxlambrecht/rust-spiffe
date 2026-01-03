//! Authorization abstractions for SPIFFE ID-based access control.

use crate::error::{AuthorizerConfigError, Result};
use spiffe::{SpiffeId, TrustDomain};
use std::collections::BTreeSet;
use std::sync::Arc;

/// Authorization policy for peer SPIFFE IDs.
///
/// Authorization runs **after** cryptographic verification succeeds.
/// Implementations must be thread-safe.
pub trait Authorizer: Send + Sync + 'static {
    /// Returns `true` if the peer SPIFFE ID is authorized.
    fn authorize(&self, peer: &SpiffeId) -> bool;
}

// ---- ergonomic blanket impl (closures / function pointers) ----

impl<F> Authorizer for F
where
    F: Fn(&SpiffeId) -> bool + Send + Sync + 'static,
{
    fn authorize(&self, peer: &SpiffeId) -> bool {
        self(peer)
    }
}

impl Authorizer for Arc<dyn Authorizer> {
    fn authorize(&self, peer: &SpiffeId) -> bool {
        (**self).authorize(peer)
    }
}

impl Authorizer for Box<dyn Authorizer> {
    fn authorize(&self, peer: &SpiffeId) -> bool {
        (**self).authorize(peer)
    }
}

/// Authorizes any SPIFFE ID (authentication only, no authorization).
#[derive(Debug, Clone, Copy, Default)]
pub struct Any;

impl Authorizer for Any {
    fn authorize(&self, _peer: &SpiffeId) -> bool {
        true
    }
}

/// Authorizes only the exact SPIFFE IDs in the allow list.
#[derive(Debug, Clone)]
pub struct Exact {
    allowed: Arc<BTreeSet<SpiffeId>>,
}

impl Exact {
    /// Creates a new `Exact` authorizer.
    ///
    /// If the iterator is empty, the authorizer authorizes nothing.
    ///
    /// # Errors
    ///
    /// Returns `Error::AuthorizerConfig` if any ID cannot be parsed.
    pub fn new<I>(ids: I) -> Result<Self>
    where
        I: IntoIterator,
        I::Item: TryInto<SpiffeId>,
        <I::Item as TryInto<SpiffeId>>::Error: std::fmt::Display,
    {
        let mut allowed = BTreeSet::new();

        for id in ids {
            let spiffe_id = id
                .try_into()
                .map_err(|e| AuthorizerConfigError::InvalidSpiffeId(e.to_string()))?;
            allowed.insert(spiffe_id);
        }

        Ok(Self {
            allowed: Arc::new(allowed),
        })
    }
}

impl Authorizer for Exact {
    fn authorize(&self, peer: &SpiffeId) -> bool {
        self.allowed.contains(peer)
    }
}

/// Authorizes any SPIFFE ID from the given trust domains.
#[derive(Debug, Clone)]
pub struct TrustDomains {
    allowed: Arc<BTreeSet<TrustDomain>>,
}

impl TrustDomains {
    /// Creates a new `TrustDomains` authorizer.
    ///
    /// If the iterator is empty, the authorizer authorizes nothing.
    ///
    /// # Errors
    ///
    /// Returns `Error::AuthorizerConfig` if any trust domain cannot be parsed.
    pub fn new<I>(domains: I) -> Result<Self>
    where
        I: IntoIterator,
        I::Item: TryInto<TrustDomain>,
        <I::Item as TryInto<TrustDomain>>::Error: std::fmt::Display,
    {
        let mut allowed = BTreeSet::new();

        for domain in domains {
            let td = domain
                .try_into()
                .map_err(|e| AuthorizerConfigError::InvalidTrustDomain(e.to_string()))?;
            allowed.insert(td);
        }

        Ok(Self {
            allowed: Arc::new(allowed),
        })
    }
}

impl Authorizer for TrustDomains {
    fn authorize(&self, peer: &SpiffeId) -> bool {
        self.allowed.contains(peer.trust_domain())
    }
}

/// Returns an authorizer that accepts any SPIFFE ID.
///
/// This is useful when authorization is performed at another layer
/// (e.g., application-level RBAC). Authentication (certificate verification)
/// still applies.
///
/// Returns a zero-sized `Any` value that can be used directly.
///
/// # Examples
///
/// ```rust
/// use spiffe_rustls::authorizer;
///
/// let auth = authorizer::any();
/// ```
pub fn any() -> Any {
    Any
}

/// Returns an authorizer that only accepts the exact SPIFFE IDs.
///
/// # Arguments
///
/// * `ids` - An iterator of SPIFFE IDs (or types that can be converted to `SpiffeId`)
///
/// If the iterator is empty, the resulting authorizer will authorize no SPIFFE IDs
/// (all authorization checks will return `false`).
///
/// # Errors
///
/// Returns `Error::AuthorizerConfig` if any SPIFFE ID is invalid.
///
/// # Examples
///
/// ```rust
/// use spiffe_rustls::authorizer;
///
/// // Pass string literals directly - exact() will convert them
/// let auth = authorizer::exact([
///     "spiffe://example.org/payment",
///     "spiffe://example.org/checkout",
/// ])?;
/// # Ok::<(), spiffe_rustls::Error>(())
/// ```
pub fn exact<I>(ids: I) -> Result<Exact>
where
    I: IntoIterator,
    I::Item: TryInto<SpiffeId>,
    <I::Item as TryInto<SpiffeId>>::Error: std::fmt::Display,
{
    Exact::new(ids)
}

/// Returns an authorizer that accepts any SPIFFE ID from the given trust domains.
///
/// # Arguments
///
/// * `domains` - An iterator of trust domains (or types that can be converted to `TrustDomain`)
///
/// If the iterator is empty, the resulting authorizer will authorize no trust domains
/// (all authorization checks will return `false`).
///
/// # Errors
///
/// Returns `Error::AuthorizerConfig` if any trust domain is invalid.
///
/// # Examples
///
/// ```rust
/// use spiffe_rustls::authorizer;
///
/// // Pass string literals directly - trust_domains() will convert them
/// let auth = authorizer::trust_domains([
///     "broker.example",
///     "stockmarket.example",
/// ])?;
/// # Ok::<(), spiffe_rustls::Error>(())
/// ```
pub fn trust_domains<I>(domains: I) -> Result<TrustDomains>
where
    I: IntoIterator,
    I::Item: TryInto<TrustDomain>,
    <I::Item as TryInto<TrustDomain>>::Error: std::fmt::Display,
{
    TrustDomains::new(domains)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_authorizer() {
        let id1 = SpiffeId::new("spiffe://example.org/service1").unwrap();
        let id2 = SpiffeId::new("spiffe://example.org/service2").unwrap();
        let id3 = SpiffeId::new("spiffe://other.org/service1").unwrap();

        let auth = Exact::new([id1.clone(), id2.clone()]).unwrap();
        assert!(auth.authorize(&id1));
        assert!(auth.authorize(&id2));
        assert!(!auth.authorize(&id3));
    }

    #[test]
    fn test_exact_authorizer_rejects_invalid() {
        let result = Exact::new(["invalid-spiffe-id", "also-invalid"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_trust_domains_authorizer() {
        let td1 = TrustDomain::new("example.org").unwrap();
        let td2 = TrustDomain::new("other.org").unwrap();

        let id1 = SpiffeId::new("spiffe://example.org/service1").unwrap();
        let id2 = SpiffeId::new("spiffe://example.org/service2").unwrap();
        let id3 = SpiffeId::new("spiffe://other.org/service1").unwrap();
        let id4 = SpiffeId::new("spiffe://third.org/service1").unwrap();

        let auth = TrustDomains::new([td1, td2]).unwrap();
        assert!(auth.authorize(&id1));
        assert!(auth.authorize(&id2));
        assert!(auth.authorize(&id3));
        assert!(!auth.authorize(&id4));
    }

    #[test]
    fn test_trust_domains_authorizer_rejects_invalid() {
        // Use a string with invalid characters (uppercase and special chars not allowed)
        // TrustDomain::new explicitly validates the format, so this should fail
        let result = TrustDomains::new(["Invalid@Trust#Domain"]);
        assert!(result.is_err());

        // Verify that valid trust domains are accepted
        let valid = TrustDomains::new(["example.org", "other.org"]).unwrap();
        let id1 = SpiffeId::new("spiffe://example.org/service").unwrap();
        let id2 = SpiffeId::new("spiffe://other.org/service").unwrap();
        let id3 = SpiffeId::new("spiffe://rejected.org/service").unwrap();
        assert!(valid.authorize(&id1));
        assert!(valid.authorize(&id2));
        assert!(!valid.authorize(&id3));
    }

    #[test]
    fn test_any_authorizer_always_authorizes() {
        // Verify that `Any` authorizer accepts all valid SPIFFE IDs regardless of trust domain
        let auth = any();
        let id1 = SpiffeId::new("spiffe://example.org/service").unwrap();
        let id2 = SpiffeId::new("spiffe://other.org/another").unwrap();
        let id3 = SpiffeId::new("spiffe://test.domain/path/to/resource").unwrap();

        // Any authorizer should accept all SPIFFE IDs
        assert!(auth.authorize(&id1));
        assert!(auth.authorize(&id2));
        assert!(auth.authorize(&id3));
    }
}
