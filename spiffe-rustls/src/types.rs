use std::sync::Arc;

/// Authorization hook for peer SPIFFE IDs.
///
/// The callback is invoked with the peer SPIFFE ID string extracted from the leaf certificate
/// (URI SAN), e.g. `spiffe://example.org/myservice`.
pub type AuthorizeSpiffeId = Arc<dyn Fn(&str) -> bool + Send + Sync + 'static>;

/// Returns an authorization hook that accepts any SPIFFE ID.
///
/// Authentication (certificate verification) still applies; this only makes the authorization step permissive.
pub fn authorize_any() -> AuthorizeSpiffeId {
    Arc::new(|_| true)
}

/// Returns an authorization hook that only accepts the given SPIFFE IDs.
pub fn authorize_exact<I, S>(ids: I) -> AuthorizeSpiffeId
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut allow: Vec<String> = ids.into_iter().map(Into::into).collect();
    allow.sort();
    allow.dedup();
    let allow = Arc::new(allow);

    Arc::new(move |id: &str| allow.binary_search(&id.to_string()).is_ok())
}
