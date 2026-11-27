//! Authorization abstractions for SPIFFE ID-based access control.

use crate::error::{AuthorizerConfigError, Result};
use spiffe::{spiffe_id::SPIFFE_SCHEME, SpiffeId, TrustDomain};
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

/// Authorizes any authenticated SPIFFE ID under the active trust-domain policy.
///
/// By default (`TrustDomainPolicy::AnyInBundleSet`), every trust domain in the source
/// bundle set is accepted.
///
/// This is the default authorizer for client and server builders. Production
/// deployments should usually configure a more specific authorizer, such as
/// [`exact`] or [`trust_domains`].
#[must_use]
#[derive(Debug, Clone, Copy, Default)]
pub struct Any;

impl Authorizer for Any {
    fn authorize(&self, _peer: &SpiffeId) -> bool {
        true
    }
}

/// Authorizes only the exact SPIFFE IDs in the allow list.
#[must_use]
#[derive(Debug, Clone)]
pub struct Exact {
    allowed: BTreeSet<SpiffeId>,
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

        Ok(Self { allowed })
    }
}

impl Authorizer for Exact {
    fn authorize(&self, peer: &SpiffeId) -> bool {
        self.allowed.contains(peer)
    }
}

/// Converts an entry for a [`TrustDomainAllowList`] into a trust domain.
///
/// Implementations for `&str` and `String` accept bare trust-domain names and
/// pathless SPIFFE IDs. A [`TrustDomain`] is accepted directly.
pub trait TryIntoAllowListTrustDomain {
    /// Converts the entry to a validated trust domain for the allow-list.
    ///
    /// # Errors
    ///
    /// Returns an [`AuthorizerConfigError`] if the entry is invalid.
    fn try_into_allow_list_trust_domain(
        self,
    ) -> std::result::Result<TrustDomain, AuthorizerConfigError>;
}

impl TryIntoAllowListTrustDomain for &str {
    fn try_into_allow_list_trust_domain(
        self,
    ) -> std::result::Result<TrustDomain, AuthorizerConfigError> {
        if self
            .split_once("://")
            .is_some_and(|(scheme, authority_and_path)| {
                scheme.eq_ignore_ascii_case(SPIFFE_SCHEME) && authority_and_path.contains('/')
            })
        {
            return Err(AuthorizerConfigError::InvalidTrustDomain(
                "SPIFFE ID contains a path".into(),
            ));
        }

        TrustDomain::new(self).map_err(|e| AuthorizerConfigError::InvalidTrustDomain(e.to_string()))
    }
}

impl TryIntoAllowListTrustDomain for String {
    fn try_into_allow_list_trust_domain(
        self,
    ) -> std::result::Result<TrustDomain, AuthorizerConfigError> {
        self.as_str().try_into_allow_list_trust_domain()
    }
}

impl TryIntoAllowListTrustDomain for TrustDomain {
    fn try_into_allow_list_trust_domain(
        self,
    ) -> std::result::Result<TrustDomain, AuthorizerConfigError> {
        Ok(self)
    }
}

/// Authorizes any SPIFFE ID whose trust domain is in the allow-list.
#[must_use]
#[derive(Debug, Clone)]
pub struct TrustDomainAllowList {
    allowed: BTreeSet<TrustDomain>,
}

/// Compatibility alias for [`TrustDomainAllowList`].
///
/// This type was renamed for clarity. New code should use
/// [`TrustDomainAllowList`] directly.
#[deprecated(
    since = "0.4.1",
    note = "Renamed to TrustDomainAllowList; TrustDomains remains as a compatibility alias."
)]
pub type TrustDomains = TrustDomainAllowList;

impl TrustDomainAllowList {
    /// Creates a new `TrustDomainAllowList` authorizer.
    ///
    /// Pass bare trust-domain names, pathless SPIFFE IDs, or [`TrustDomain`] values.
    /// To intentionally extract a domain from a workload SPIFFE ID, pass the result
    /// of [`TrustDomain::new`]. Callers with a custom `TryInto<TrustDomain>` converter
    /// can convert their entries to `TrustDomain` before calling this constructor.
    ///
    /// If the iterator is empty, the authorizer authorizes nothing.
    ///
    /// # Errors
    ///
    /// Returns `Error::AuthorizerConfig` if any entry is invalid or a SPIFFE ID
    /// string contains a path, including a trailing slash.
    pub fn new<I>(domains: I) -> Result<Self>
    where
        I: IntoIterator,
        I::Item: TryIntoAllowListTrustDomain,
    {
        let mut allowed = BTreeSet::new();

        for domain in domains {
            allowed.insert(domain.try_into_allow_list_trust_domain()?);
        }

        Ok(Self { allowed })
    }
}

impl Authorizer for TrustDomainAllowList {
    fn authorize(&self, peer: &SpiffeId) -> bool {
        self.allowed.contains(peer.trust_domain())
    }
}

/// Returns an authorizer that accepts any authenticated SPIFFE ID.
///
/// The peer's trust domain must be accepted by the configured trust-domain policy.
/// By default (`TrustDomainPolicy::AnyInBundleSet`), every trust domain in the source
/// bundle set is accepted.
///
/// This is useful when authorization is performed at another layer
/// (e.g., application-level RBAC). Authentication (certificate verification)
/// still applies.
///
/// This is the default authorizer for client and server builders. Production
/// deployments should usually configure a more specific authorizer.
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
pub const fn any() -> Any {
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
/// Pass bare trust-domain names, pathless SPIFFE IDs, or [`TrustDomain`] values.
/// For intentional domain extraction or migration from a custom `TryInto<TrustDomain>`
/// converter, see [`TrustDomainAllowList::new`].
///
/// If the iterator is empty, the resulting authorizer will authorize no trust domains
/// (all authorization checks will return `false`).
///
/// # Errors
///
/// Returns `Error::AuthorizerConfig` if any entry is invalid or a SPIFFE ID string
/// contains a path, including a trailing slash.
///
/// # Examples
///
/// ```rust
/// use spiffe_rustls::authorizer;
///
/// // Pass string literals directly - trust_domains() will convert them
/// let auth = authorizer::trust_domains([
///     "broker.example",
///     "spiffe://stockmarket.example",
/// ])?;
/// # Ok::<(), spiffe_rustls::Error>(())
/// ```
pub fn trust_domains<I>(domains: I) -> Result<TrustDomainAllowList>
where
    I: IntoIterator,
    I::Item: TryIntoAllowListTrustDomain,
{
    TrustDomainAllowList::new(domains)
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
        result.unwrap_err();
    }

    #[test]
    fn test_trust_domains_authorizer() {
        let td1 = TrustDomain::new("example.org").unwrap();
        let td2 = TrustDomain::new("other.org").unwrap();

        let id1 = SpiffeId::new("spiffe://example.org/service1").unwrap();
        let id2 = SpiffeId::new("spiffe://example.org/service2").unwrap();
        let id3 = SpiffeId::new("spiffe://other.org/service1").unwrap();
        let id4 = SpiffeId::new("spiffe://third.org/service1").unwrap();

        let auth = TrustDomainAllowList::new([td1, td2]).unwrap();
        assert!(auth.authorize(&id1));
        assert!(auth.authorize(&id2));
        assert!(auth.authorize(&id3));
        assert!(!auth.authorize(&id4));
    }

    #[test]
    fn test_trust_domains_authorizer_rejects_invalid() {
        // Use a string with invalid characters (uppercase and special chars not allowed)
        // TrustDomain::new explicitly validates the format, so this should fail
        let result = TrustDomainAllowList::new(["Invalid@Trust#Domain"]);
        result.unwrap_err();

        // Verify that valid trust domains are accepted
        let valid = TrustDomainAllowList::new(["example.org", "other.org"]).unwrap();
        let id1 = SpiffeId::new("spiffe://example.org/service").unwrap();
        let id2 = SpiffeId::new("spiffe://other.org/service").unwrap();
        let id3 = SpiffeId::new("spiffe://rejected.org/service").unwrap();
        assert!(valid.authorize(&id1));
        assert!(valid.authorize(&id2));
        assert!(!valid.authorize(&id3));
    }

    #[test]
    fn test_trust_domains_authorizer_rejects_borrowed_path() {
        for input in [
            "spiffe://example.org/workload",
            "SpIfFe://EXAMPLE.ORG/workload",
            "spiffe://example.org/",
        ] {
            let result = TrustDomainAllowList::new([input]);
            assert!(
                matches!(
                    result,
                    Err(crate::Error::AuthorizerConfig(
                        AuthorizerConfigError::InvalidTrustDomain(_)
                    ))
                ),
                "expected an authorizer configuration error for {input}, got {result:?}"
            );
        }
    }

    #[test]
    fn test_trust_domains_authorizer_rejects_owned_path() {
        let result = trust_domains([String::from("spiffe://example.org/workload")]);
        assert!(
            matches!(
                result,
                Err(crate::Error::AuthorizerConfig(
                    AuthorizerConfigError::InvalidTrustDomain(_)
                ))
            ),
            "expected an authorizer configuration error, got {result:?}"
        );
    }

    #[test]
    fn test_trust_domains_authorizer_rejects_path_even_with_matching_bare_domain() {
        let result = TrustDomainAllowList::new(["example.org", "spiffe://example.org/workload"]);
        assert!(matches!(
            result,
            Err(crate::Error::AuthorizerConfig(
                AuthorizerConfigError::InvalidTrustDomain(message)
            )) if message.contains("contains a path")
        ));
    }

    #[test]
    fn test_trust_domains_authorizer_accepts_canonical_duplicates() {
        let domains = ["EXAMPLE.ORG", "SpIfFe://example.org"];
        let allowed = SpiffeId::new("spiffe://example.org/workload").unwrap();
        let denied = SpiffeId::new("spiffe://other.org/workload").unwrap();
        for auth in [
            TrustDomainAllowList::new(domains).unwrap(),
            trust_domains(domains.map(String::from)).unwrap(),
        ] {
            assert_eq!(auth.allowed.len(), 1);
            assert_eq!(auth.allowed.first().unwrap().as_str(), "example.org");
            assert!(auth.authorize(&allowed));
            assert!(!auth.authorize(&denied));
        }
    }

    #[test]
    fn test_trust_domains_authorizer_accepts_explicit_domain_extracted_from_path() {
        let domain = TrustDomain::new("spiffe://EXAMPLE.ORG/workload").unwrap();
        assert_eq!(domain.as_str(), "example.org");
        let auth = TrustDomainAllowList::new([domain]).unwrap();
        assert!(auth.authorize(&SpiffeId::new("spiffe://example.org/another").unwrap()));
    }

    #[test]
    fn test_trust_domains_authorizer_accepts_explicitly_converted_custom_entry() {
        struct ConfigDomain<'a>(&'a str);

        impl TryFrom<ConfigDomain<'_>> for TrustDomain {
            type Error = spiffe::SpiffeIdError;

            fn try_from(domain: ConfigDomain<'_>) -> std::result::Result<Self, Self::Error> {
                Self::new(domain.0)
            }
        }

        let config = String::from("example.org");
        let domain = TrustDomain::try_from(ConfigDomain(&config)).unwrap();
        let auth = TrustDomainAllowList::new([domain]).unwrap();
        assert!(auth.authorize(&SpiffeId::new("spiffe://example.org/workload").unwrap()));
    }

    #[test]
    fn test_local_only_still_accepts_domain_converted_from_path() {
        let policy = crate::LocalOnly("spiffe://example.org/workload".try_into().unwrap());
        assert!(policy.allows(&TrustDomain::new("example.org").unwrap()));
        assert!(!policy.allows(&TrustDomain::new("other.org").unwrap()));
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
