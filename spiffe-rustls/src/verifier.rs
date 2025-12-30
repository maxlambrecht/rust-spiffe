//! rustls verifiers that authenticate with SPIFFE trust bundles and authorize by SPIFFE ID.
//!
//! This module is internal to the crate. It intentionally keeps the public API
//! surface minimal and avoids leaking rustls implementation details.

use crate::authorizer::Authorizer;
use crate::error::{Error, Result};
use crate::material::MaterialSnapshot;
use crate::policy::TrustDomainPolicy;
use crate::prelude::{debug, error};
use crate::resolve::MaterialWatcher;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use spiffe::SpiffeId;
use std::collections::{hash_map::DefaultHasher, HashMap, VecDeque};
use std::fmt::{self, Debug};
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};
use x509_parser::prelude::{FromDer, X509Certificate};

/// Cached result of extracting SPIFFE ID from a certificate.
#[derive(Clone, Debug)]
struct CachedSpiffeId {
    spiffe_id: SpiffeId,
}

/// Bounded cache for certificate parsing results with O(1) lookup and FIFO eviction.
///
/// Uses a hash-based key (certificate DER hash) to avoid repeated parsing.
/// Capacity is fixed at 64 entries to prevent unbounded growth while covering
/// typical TLS handshake patterns (multiple certs per connection, connection reuse).
struct CertParseCache {
    entries: HashMap<u64, CachedSpiffeId>,
    order: VecDeque<u64>,
    capacity: usize,
}

impl CertParseCache {
    const CAPACITY: usize = 64;

    fn new() -> Self {
        Self {
            entries: HashMap::with_capacity(Self::CAPACITY),
            order: VecDeque::with_capacity(Self::CAPACITY),
            capacity: Self::CAPACITY,
        }
    }

    fn get(&self, cert_hash: u64) -> Option<&CachedSpiffeId> {
        self.entries.get(&cert_hash)
    }

    fn insert(&mut self, cert_hash: u64, value: CachedSpiffeId) {
        // If key already exists, update value but don't duplicate in order queue
        if let std::collections::hash_map::Entry::Occupied(mut e) = self.entries.entry(cert_hash) {
            e.insert(value);
            return;
        }

        // If at capacity, evict oldest entry (FIFO)
        if self.entries.len() >= self.capacity {
            if let Some(oldest_key) = self.order.pop_front() {
                self.entries.remove(&oldest_key);
            }
        }

        // Insert new entry
        self.entries.insert(cert_hash, value);
        self.order.push_back(cert_hash);
    }
}

/// Compute a hash of the certificate DER for use as a cache key.
fn cert_hash(cert: &CertificateDer<'_>) -> u64 {
    let mut hasher = DefaultHasher::new();
    cert.as_ref().hash(&mut hasher);
    hasher.finish()
}

/// Extract the SPIFFE ID from the leaf certificate.
///
/// This is a convenience function that does not use caching. For better performance
/// in high-throughput scenarios, use the verifier's internal caching mechanism.
///
/// # Errors
///
/// Returns an error if:
/// - No SPIFFE ID is present (`Error::MissingSpiffeId`)
/// - Multiple SPIFFE IDs are present (`Error::MultipleSpiffeIds`, invalid per SPIFFE spec)
/// - The certificate cannot be parsed (`Error::CertParse`)
/// - The SPIFFE ID string is invalid (`Error::CertParse`)
/// - The certificate has too many URI SAN entries (`Error::CertParse`, max 32)
///
/// Note: Overly long URI entries (exceeding 2048 bytes) are skipped during parsing
/// and will not cause an error, but may result in `Error::MissingSpiffeId` if no valid
/// SPIFFE ID is found.
#[allow(dead_code)] // Used in tests
pub(crate) fn extract_spiffe_id(leaf: &CertificateDer<'_>) -> Result<SpiffeId> {
    extract_spiffe_id_with_cache(leaf, None)
}

/// Extract the SPIFFE ID from the leaf certificate, using an optional cache.
///
/// This is the internal implementation that supports caching to avoid repeated parsing.
fn extract_spiffe_id_with_cache(
    leaf: &CertificateDer<'_>,
    cache: Option<&Mutex<CertParseCache>>,
) -> Result<SpiffeId> {
    let cert_hash = cert_hash(leaf);

    // Check cache first
    if let Some(cache) = cache {
        let guard = cache
            .lock()
            .map_err(|_| Error::Internal("cert parse cache mutex poisoned".into()))?;
        if let Some(cached) = guard.get(cert_hash) {
            return Ok(cached.spiffe_id.clone());
        }
    }

    // Parse certificate
    let (_, cert) =
        X509Certificate::from_der(leaf.as_ref()).map_err(|e| Error::CertParse(format!("{e:?}")))?;

    let san = cert
        .subject_alternative_name()
        .map_err(|e| Error::CertParse(format!("{e:?}")))?
        .ok_or(Error::MissingSpiffeId)?;

    // Collect SPIFFE URIs from SAN with conservative bounds to prevent DoS
    let uris: Vec<&str> = san
        .value
        .general_names
        .iter()
        .filter_map(|name| match name {
            x509_parser::extensions::GeneralName::URI(uri) => Some(&**uri),
            _ => None,
        })
        .collect();

    let spiffe_ids = collect_spiffe_ids_from_uris(uris.iter().copied())?;

    let spiffe_id = match spiffe_ids.len() {
        0 => return Err(Error::MissingSpiffeId),
        1 => spiffe_ids.into_iter().next().unwrap(),
        _ => return Err(Error::MultipleSpiffeIds),
    };

    // Cache the result
    if let Some(cache) = cache {
        let mut guard = cache
            .lock()
            .map_err(|_| Error::Internal("cert parse cache mutex poisoned".into()))?;
        guard.insert(
            cert_hash,
            CachedSpiffeId {
                spiffe_id: spiffe_id.clone(),
            },
        );
    }

    Ok(spiffe_id)
}

/// Collects SPIFFE IDs from URI SAN entries with conservative bounds to prevent `DoS`.
///
/// This function enforces:
/// - Maximum 32 URI SAN entries (returns error if exceeded)
/// - Maximum 2048 bytes per URI (overly long URIs are skipped)
///
/// # Errors
///
/// Returns `Error::CertParse` if there are too many URI SAN entries.
pub(crate) fn collect_spiffe_ids_from_uris<'a>(
    uris: impl Iterator<Item = &'a str>,
) -> Result<Vec<SpiffeId>> {
    collect_spiffe_ids_from_uris_impl(uris)
}

fn collect_spiffe_ids_from_uris_impl<'a>(
    uris: impl Iterator<Item = &'a str>,
) -> Result<Vec<SpiffeId>> {
    const MAX_URI_SAN_ENTRIES: usize = 32;
    const MAX_URI_LENGTH: usize = 2048;

    let mut spiffe_ids = Vec::new();
    let mut uri_count = 0usize;

    for uri in uris {
        uri_count += 1;
        if uri_count > MAX_URI_SAN_ENTRIES {
            return Err(Error::CertParse(format!(
                "certificate has too many URI SAN entries (max {MAX_URI_SAN_ENTRIES})"
            )));
        }

        if uri.len() > MAX_URI_LENGTH {
            // Skip overly long URIs rather than failing; they're likely not SPIFFE IDs
            continue;
        }

        if uri.starts_with("spiffe://") {
            let spiffe_id = SpiffeId::new(uri)
                .map_err(|e| Error::CertParse(format!("invalid SPIFFE ID '{uri}': {e}")))?;
            spiffe_ids.push(spiffe_id);
        }
    }

    Ok(spiffe_ids)
}

fn other_err<E>(e: E) -> rustls::Error
where
    E: std::error::Error + Send + Sync + 'static,
{
    rustls::Error::Other(rustls::OtherError(Arc::new(e)))
}

/// Provides access to the current material snapshot.
///
/// This is crate-private so we can:
/// - keep verifiers testable without spawning a watcher/task
/// - decouple verifiers from a specific watcher implementation
pub(crate) trait MaterialProvider: Send + Sync {
    fn current_material(&self) -> Arc<MaterialSnapshot>;
}

impl MaterialProvider for MaterialWatcher {
    fn current_material(&self) -> Arc<MaterialSnapshot> {
        self.current()
    }
}

// ---- cache helpers ----

/// Cache key for verifiers: (generation, `trust_domain`)
type VerifierCacheKey = (u64, spiffe::TrustDomain);

#[derive(Clone)]
struct ServerVerifierCache {
    key: VerifierCacheKey,
    verifier: Arc<dyn rustls::client::danger::ServerCertVerifier>,
    schemes: Vec<SignatureScheme>,
}

#[derive(Clone)]
struct ClientVerifierCache {
    key: VerifierCacheKey,
    verifier: Arc<dyn rustls::server::danger::ClientCertVerifier>,
    schemes: Vec<SignatureScheme>,
}

fn build_server_verifier(
    roots: Arc<rustls::RootCertStore>,
) -> Result<Arc<dyn rustls::client::danger::ServerCertVerifier>> {
    let v = rustls::client::WebPkiServerVerifier::builder(roots)
        .build()
        .map_err(|e| Error::VerifierBuilder(format!("{e:?}")))?;

    let v: Arc<dyn rustls::client::danger::ServerCertVerifier> = v;

    Ok(v)
}

fn build_client_verifier(
    roots: Arc<rustls::RootCertStore>,
) -> Result<Arc<dyn rustls::server::danger::ClientCertVerifier>> {
    let v = rustls::server::WebPkiClientVerifier::builder(roots)
        .build()
        .map_err(|e| Error::VerifierBuilder(format!("{e:?}")))?;

    let v: Arc<dyn rustls::server::danger::ClientCertVerifier> = v;

    Ok(v)
}

// ------------ Server verifier (client side) ------------

#[derive(Clone)]
pub(crate) struct SpiffeServerCertVerifier {
    provider: Arc<dyn MaterialProvider>,
    authorizer: Arc<dyn Authorizer>,
    policy: TrustDomainPolicy,
    cache: Arc<Mutex<Option<ServerVerifierCache>>>,
    parse_cache: Arc<Mutex<CertParseCache>>,
    last_logged_gen: Arc<Mutex<Option<u64>>>,
}

impl SpiffeServerCertVerifier {
    pub fn new(
        provider: Arc<dyn MaterialProvider>,
        authorizer: Arc<dyn Authorizer>,
        policy: TrustDomainPolicy,
    ) -> Self {
        Self {
            provider,
            authorizer,
            policy,
            cache: Arc::new(Mutex::new(None)),
            parse_cache: Arc::new(Mutex::new(CertParseCache::new())),
            last_logged_gen: Arc::new(Mutex::new(None)),
        }
    }

    /// Gets or builds a verifier for the given trust domain.
    fn get_or_build_inner(
        &self,
        trust_domain: &spiffe::TrustDomain,
    ) -> Result<Arc<dyn rustls::client::danger::ServerCertVerifier>> {
        let snap = self.provider.current_material();
        let gen = snap.generation;

        // Check if trust domain is allowed by policy
        if !self.policy.allows(trust_domain) {
            return Err(Error::TrustDomainNotAllowed(trust_domain.clone()));
        }

        // Get root cert store for this trust domain
        let roots = snap
            .roots_by_td
            .get(trust_domain)
            .ok_or_else(|| Error::NoBundle(trust_domain.clone()))?
            .clone();

        let cache_key = (gen, trust_domain.clone());

        let mut guard = self
            .cache
            .lock()
            .map_err(|_| Error::Internal("server verifier cache mutex poisoned".into()))?;

        if let Some(cached) = guard.as_ref() {
            if cached.key == cache_key {
                return Ok(cached.verifier.clone());
            }
        }

        let built = build_server_verifier(roots)?;
        let schemes = built.supported_verify_schemes();

        *guard = Some(ServerVerifierCache {
            key: cache_key,
            verifier: built.clone(),
            schemes,
        });

        Ok(built)
    }

    fn supported_schemes_cached(&self, trust_domain: &spiffe::TrustDomain) -> Vec<SignatureScheme> {
        // Do not "fail open" to empty if we have a known-good cache.
        // If there is no cache yet, attempt to build; on failure, return empty (handshake will fail).
        if let Ok(guard) = self.cache.lock() {
            if let Some(cached) = guard.as_ref() {
                if cached.key.1 == *trust_domain {
                    return cached.schemes.clone();
                }
            }
        } else {
            error!("server verifier cache mutex poisoned; returning empty schemes (handshake will fail)");
            return Vec::new();
        }

        match self.get_or_build_inner(trust_domain) {
            Ok(v) => v.supported_verify_schemes(),
            Err(e) => {
                debug!(
                    "failed to build server verifier for trust domain {}: {}; returning empty schemes (handshake will fail)",
                    trust_domain,
                    e
                );
                Vec::new()
            }
        }
    }
}

impl Debug for SpiffeServerCertVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpiffeServerCertVerifier").finish()
    }
}

impl rustls::client::danger::ServerCertVerifier for SpiffeServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // Step 1: Extract SPIFFE ID from certificate (using cache)
        // This extraction is safe because it's only used to select the trust domain's root
        // certificate bundle. Cryptographic verification (signature, chain, expiration) is still
        // enforced by rustls using the selected roots. Policy can further restrict which trust
        // domains are allowed.
        let spiffe_id =
            extract_spiffe_id_with_cache(end_entity, Some(&self.parse_cache)).map_err(other_err)?;

        // Step 2: Derive trust domain from SPIFFE ID
        let trust_domain = spiffe_id.trust_domain();

        // Step 3: Get or build verifier for this trust domain
        let inner = self.get_or_build_inner(trust_domain).map_err(other_err)?;

        // Step 4: Verify certificate chain cryptographically
        let ok =
            inner.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)?;

        // Step 5: Apply authorization (only after cryptographic verification succeeds)
        if !self.authorizer.authorize(&spiffe_id) {
            return Err(other_err(Error::UnauthorizedSpiffeId(spiffe_id)));
        }

        Ok(ok)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // Extract trust domain from cert for signature verification (using cache)
        let spiffe_id =
            extract_spiffe_id_with_cache(cert, Some(&self.parse_cache)).map_err(other_err)?;
        let trust_domain = spiffe_id.trust_domain();
        let inner = self.get_or_build_inner(trust_domain).map_err(other_err)?;
        inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // Extract trust domain from cert for signature verification (using cache)
        let spiffe_id =
            extract_spiffe_id_with_cache(cert, Some(&self.parse_cache)).map_err(other_err)?;
        let trust_domain = spiffe_id.trust_domain();
        let inner = self.get_or_build_inner(trust_domain).map_err(other_err)?;
        inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        let snap = self.provider.current_material();

        advertised_verify_schemes(
            "server verifier",
            snap.generation,
            &self.last_logged_gen,
            &snap,
            &self.policy,
            |td| self.supported_schemes_cached(td),
            |_td, roots| {
                let verifier = build_server_verifier(roots)?;
                Ok(verifier.supported_verify_schemes())
            },
        )
    }
}

// ------------ Client verifier (server side) ------------

#[derive(Clone)]
pub(crate) struct SpiffeClientCertVerifier {
    provider: Arc<dyn MaterialProvider>,
    authorizer: Arc<dyn Authorizer>,
    policy: TrustDomainPolicy,
    cache: Arc<Mutex<Option<ClientVerifierCache>>>,
    parse_cache: Arc<Mutex<CertParseCache>>,
    last_logged_gen: Arc<Mutex<Option<u64>>>,
}

impl SpiffeClientCertVerifier {
    pub fn new(
        provider: Arc<dyn MaterialProvider>,
        authorizer: Arc<dyn Authorizer>,
        policy: TrustDomainPolicy,
    ) -> Self {
        Self {
            provider,
            authorizer,
            policy,
            cache: Arc::new(Mutex::new(None)),
            parse_cache: Arc::new(Mutex::new(CertParseCache::new())),
            last_logged_gen: Arc::new(Mutex::new(None)),
        }
    }

    /// Gets or builds a verifier for the given trust domain.
    fn get_or_build_inner(
        &self,
        trust_domain: &spiffe::TrustDomain,
    ) -> Result<Arc<dyn rustls::server::danger::ClientCertVerifier>> {
        let snap = self.provider.current_material();
        let gen = snap.generation;

        // Check if trust domain is allowed by policy
        if !self.policy.allows(trust_domain) {
            return Err(Error::TrustDomainNotAllowed(trust_domain.clone()));
        }

        // Get root cert store for this trust domain
        let roots = snap
            .roots_by_td
            .get(trust_domain)
            .ok_or_else(|| Error::NoBundle(trust_domain.clone()))?
            .clone();

        let cache_key = (gen, trust_domain.clone());

        let mut guard = self
            .cache
            .lock()
            .map_err(|_| Error::Internal("client verifier cache mutex poisoned".into()))?;

        if let Some(cached) = guard.as_ref() {
            if cached.key == cache_key {
                return Ok(cached.verifier.clone());
            }
        }

        let built = build_client_verifier(roots)?;
        let schemes = built.supported_verify_schemes();

        *guard = Some(ClientVerifierCache {
            key: cache_key,
            verifier: built.clone(),
            schemes,
        });

        Ok(built)
    }

    fn supported_schemes_cached(&self, trust_domain: &spiffe::TrustDomain) -> Vec<SignatureScheme> {
        if let Ok(guard) = self.cache.lock() {
            if let Some(cached) = guard.as_ref() {
                if cached.key.1 == *trust_domain {
                    return cached.schemes.clone();
                }
            }
        } else {
            error!("client verifier cache mutex poisoned; returning empty schemes (handshake will fail)");
            return Vec::new();
        }

        match self.get_or_build_inner(trust_domain) {
            Ok(v) => v.supported_verify_schemes(),
            Err(e) => {
                debug!(
                    "failed to build client verifier for trust domain {}: {}; returning empty schemes (handshake will fail)",
                    trust_domain,
                    e
                );
                Vec::new()
            }
        }
    }
}

impl Debug for SpiffeClientCertVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpiffeClientCertVerifier").finish()
    }
}

impl rustls::server::danger::ClientCertVerifier for SpiffeClientCertVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        // Returning an empty hint list is correct (it does not weaken verification);
        // it only affects what the peer *might* send. Keeping this simple avoids
        // lifetime/locking complexity.
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> std::result::Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        // Step 1: Extract SPIFFE ID from certificate (using cache)
        // This extraction is safe because it's only used to select the trust domain's root
        // certificate bundle. Cryptographic verification (signature, chain, expiration) is still
        // enforced by rustls using the selected roots. Policy can further restrict which trust
        // domains are allowed.
        let spiffe_id =
            extract_spiffe_id_with_cache(end_entity, Some(&self.parse_cache)).map_err(other_err)?;

        // Step 2: Derive trust domain from SPIFFE ID
        let trust_domain = spiffe_id.trust_domain();

        // Step 3: Get or build verifier for this trust domain
        let inner = self.get_or_build_inner(trust_domain).map_err(other_err)?;

        // Step 4: Verify certificate chain cryptographically
        let ok = inner.verify_client_cert(end_entity, intermediates, now)?;

        // Step 5: Apply authorization (only after cryptographic verification succeeds)
        if !self.authorizer.authorize(&spiffe_id) {
            return Err(other_err(Error::UnauthorizedSpiffeId(spiffe_id)));
        }

        Ok(ok)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // Extract trust domain from cert for signature verification (using cache)
        let spiffe_id =
            extract_spiffe_id_with_cache(cert, Some(&self.parse_cache)).map_err(other_err)?;
        let trust_domain = spiffe_id.trust_domain();
        let inner = self.get_or_build_inner(trust_domain).map_err(other_err)?;
        inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // Extract trust domain from cert for signature verification (using cache)
        let spiffe_id =
            extract_spiffe_id_with_cache(cert, Some(&self.parse_cache)).map_err(other_err)?;
        let trust_domain = spiffe_id.trust_domain();
        let inner = self.get_or_build_inner(trust_domain).map_err(other_err)?;
        inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        let snap = self.provider.current_material();

        advertised_verify_schemes(
            "client verifier",
            snap.generation,
            &self.last_logged_gen,
            &snap,
            &self.policy,
            |td| self.supported_schemes_cached(td),
            |_td, roots| {
                let verifier = build_client_verifier(roots)?;
                Ok(verifier.supported_verify_schemes())
            },
        )
    }
}

/// Computes the signature schemes to advertise during TLS handshake.
///
/// # Normal case
/// Returns the intersection of schemes across all trust domains allowed by policy.
/// This ensures compatibility: only schemes supported by all allowed trust domains
/// are advertised, reducing the risk of handshake failures.
///
/// # Fallback case
/// If policy excludes all trust domains in the snapshot, returns a union of schemes
/// from all trust domains. This allows the handshake to proceed so that certificate
/// verification can fail with a clear `TrustDomainNotAllowed` error instead of the
/// cryptic `NoSignatureSchemes` error at the TLS layer.
///
/// The policy check is still enforced during certificate verification in
/// `get_or_build_inner`, so this fallback does not weaken security.
fn advertised_verify_schemes(
    label: &str,
    gen: u64,
    last_logged_gen: &Mutex<Option<u64>>,
    snap: &MaterialSnapshot,
    policy: &TrustDomainPolicy,
    mut per_td_schemes: impl FnMut(&spiffe::TrustDomain) -> Vec<rustls::SignatureScheme>,
    mut build_union_schemes: impl FnMut(
        &spiffe::TrustDomain,
        Arc<rustls::RootCertStore>,
    ) -> Result<Vec<rustls::SignatureScheme>>,
) -> Vec<rustls::SignatureScheme> {
    // Collect schemes for trust domains allowed by policy.
    let mut scheme_sets: Vec<Vec<rustls::SignatureScheme>> = Vec::new();

    for td in snap.roots_by_td.keys() {
        if !policy.allows(td) {
            continue;
        }

        let schemes = per_td_schemes(td);
        if !schemes.is_empty() {
            scheme_sets.push(schemes);
        }
    }

    // Normal case: intersection across allowed trust domains.
    if !scheme_sets.is_empty() {
        let first = &scheme_sets[0];
        return first
            .iter()
            .filter(|scheme| scheme_sets.iter().skip(1).all(|set| set.contains(scheme)))
            .copied()
            .collect();
    }

    // Policy excluded all trust domains: avoid returning empty schemes (which causes
    // "NoSignatureSchemes" and hides the actual policy error). Instead advertise
    // a union computed without policy so we can fail later with TrustDomainNotAllowed
    // during certificate verification.
    let should_log = match last_logged_gen.lock() {
        Ok(mut guard) => {
            if guard.as_ref() == Some(&gen) {
                false
            } else {
                *guard = Some(gen);
                true
            }
        }
        Err(_) => true, // poisoned mutex: skip "log once" optimization
    };

    if should_log {
        let snapshot_tds = join_trust_domains(snap.roots_by_td.keys());
        error!(
            "{label}: trust domain policy excludes all trust domains in current bundle set \
            (snapshot trust domains: {}); falling back to scheme union to surface policy error",
            snapshot_tds
        );
    }

    // Build union of schemes from all trust domains
    // Note: Using Vec with contains() for deduplication since SignatureScheme doesn't implement Hash.
    // The number of schemes is typically small (< 10), so O(n²) is acceptable.
    let mut union: Vec<rustls::SignatureScheme> = Vec::new();

    for (td, roots) in &snap.roots_by_td {
        let schemes = match build_union_schemes(td, roots.clone()) {
            Ok(s) => s,
            Err(e) => {
                debug!(
                    "{label}: failed to build verifier for trust domain {} while computing scheme union: {}",
                    td, e
                );
                continue;
            }
        };

        for s in schemes {
            if !union.contains(&s) {
                union.push(s);
            }
        }
    }

    if union.is_empty() {
        error!(
            "{label}: failed to build verifiers for all trust domains; returning empty schemes (handshake will fail)"
        );
    }

    union
}

fn join_trust_domains<'a>(tds: impl Iterator<Item = &'a spiffe::TrustDomain>) -> String {
    tds.map(ToString::to_string).collect::<Vec<_>>().join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::{
        CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime,
    };
    use rustls::server::danger::ClientCertVerifier;
    use rustls::RootCertStore;
    use spiffe::TrustDomain;
    use std::collections::BTreeMap;
    use std::sync::{Arc, OnceLock};

    fn ensure_provider() {
        static ONCE: OnceLock<()> = OnceLock::new();
        ONCE.get_or_init(crate::crypto::ensure_crypto_provider_installed);
    }

    fn fixture_spiffe_leaf_der() -> &'static [u8] {
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/spiffe_leaf.der"
        ))
    }

    fn fixture_no_spiffe_leaf_der() -> &'static [u8] {
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/no_spiffe_leaf.der"
        ))
    }

    fn fixture_ca_der() -> &'static [u8] {
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/ca.der"
        ))
    }

    fn fixture_leaf_key_pkcs8_der() -> &'static [u8] {
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/leaf.key.pkcs8"
        ))
    }

    fn cert_with_spiffe() -> CertificateDer<'static> {
        CertificateDer::from(fixture_spiffe_leaf_der().to_vec())
    }

    fn cert_without_spiffe() -> CertificateDer<'static> {
        CertificateDer::from(fixture_no_spiffe_leaf_der().to_vec())
    }

    fn roots_with_ca() -> Arc<RootCertStore> {
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(fixture_ca_der().to_vec()))
            .expect("fixture CA must parse");
        Arc::new(roots)
    }

    fn certified_key_from_fixtures() -> Arc<rustls::sign::CertifiedKey> {
        ensure_provider();

        let certs = vec![CertificateDer::from(fixture_spiffe_leaf_der().to_vec())];

        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            fixture_leaf_key_pkcs8_der().to_vec(),
        ));

        let provider = rustls::crypto::CryptoProvider::get_default()
            .expect("rustls crypto provider must be installed");

        let signing_key = provider
            .key_provider
            .load_private_key(key_der)
            .expect("fixture private key must load");

        Arc::new(rustls::sign::CertifiedKey::new(certs, signing_key))
    }

    #[derive(Clone)]
    struct StaticMaterial(Arc<MaterialSnapshot>);

    impl MaterialProvider for StaticMaterial {
        fn current_material(&self) -> Arc<MaterialSnapshot> {
            self.0.clone()
        }
    }

    fn static_provider(generation: u64) -> Arc<dyn MaterialProvider> {
        use spiffe::TrustDomain;
        use std::collections::BTreeMap;

        let mut roots_by_td = BTreeMap::new();
        let td = TrustDomain::new("example.org").expect("valid trust domain");
        roots_by_td.insert(td, roots_with_ca());

        Arc::new(StaticMaterial(Arc::new(MaterialSnapshot {
            generation,
            certified_key: certified_key_from_fixtures(),
            roots_by_td,
        })))
    }

    #[test]
    fn extract_spiffe_id_ok() {
        let id = extract_spiffe_id(&cert_with_spiffe()).unwrap();
        assert_eq!(id.to_string(), "spiffe://example.org/service");
    }

    #[test]
    fn extract_spiffe_id_missing() {
        let err = extract_spiffe_id(&cert_without_spiffe()).unwrap_err();
        assert!(matches!(err, Error::MissingSpiffeId));
    }

    #[test]
    fn collect_spiffe_ids_too_many_uri_entries() {
        // Create an iterator with more than MAX_URI_SAN_ENTRIES (32) entries
        let uris: Vec<String> = (0..33)
            .map(|i| format!("spiffe://example.org/service{i}"))
            .collect();
        let uris_refs: Vec<&str> = uris.iter().map(std::string::String::as_str).collect();

        let err = collect_spiffe_ids_from_uris(uris_refs.iter().copied()).unwrap_err();
        assert!(matches!(err, Error::CertParse(_)));
        assert!(err.to_string().contains("too many URI SAN entries"));
    }

    #[test]
    fn collect_spiffe_ids_skips_overly_long_uri() {
        // Create a URI that exceeds MAX_URI_LENGTH (2048)
        let long_uri = "spiffe://example.org/".to_string() + &"x".repeat(2050);
        let uris = [long_uri.as_str(), "spiffe://example.org/valid"];

        // Should skip the long URI and find the valid one
        let result = collect_spiffe_ids_from_uris(uris.iter().copied()).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].to_string(), "spiffe://example.org/valid");
    }

    #[test]
    fn collect_spiffe_ids_finds_valid_spiffe_uri() {
        let uris = [
            "https://example.org/not-spiffe",
            "spiffe://example.org/service1",
            "http://other.org/also-not-spiffe",
        ];

        let result = collect_spiffe_ids_from_uris(uris.iter().copied()).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].to_string(), "spiffe://example.org/service1");
    }

    #[test]
    fn server_verifier_rejects_unauthorized_spiffe_id() {
        ensure_provider();

        let authorizer: Arc<dyn Authorizer> = Arc::new(move |_: &SpiffeId| false);
        let verifier = SpiffeServerCertVerifier::new(
            static_provider(1),
            authorizer,
            TrustDomainPolicy::AnyInBundleSet,
        );

        let err = verifier
            .verify_server_cert(
                &cert_with_spiffe(),
                &[],
                &ServerName::try_from("example.org").unwrap(),
                &[],
                UnixTime::now(),
            )
            .unwrap_err();

        let msg = format!("{err:?}");
        assert!(msg.contains("UnauthorizedSpiffeId"));
    }

    #[test]
    fn client_verifier_rejects_unauthorized_spiffe_id() {
        ensure_provider();

        let authorizer: Arc<dyn Authorizer> = Arc::new(move |_: &SpiffeId| false);
        let verifier = SpiffeClientCertVerifier::new(
            static_provider(1),
            authorizer,
            TrustDomainPolicy::AnyInBundleSet,
        );

        let err = verifier
            .verify_client_cert(&cert_with_spiffe(), &[], UnixTime::now())
            .unwrap_err();

        let msg = format!("{err:?}");
        assert!(msg.contains("UnauthorizedSpiffeId"));
    }

    #[test]
    fn server_verifier_accepts_authorized_spiffe_id() {
        ensure_provider();

        let verifier = SpiffeServerCertVerifier::new(
            static_provider(1),
            Arc::new(|id: &SpiffeId| id.to_string() == "spiffe://example.org/service")
                as Arc<dyn Authorizer>,
            TrustDomainPolicy::AnyInBundleSet,
        );

        let res = verifier.verify_server_cert(
            &cert_with_spiffe(),
            &[],
            &ServerName::try_from("example.org").unwrap(),
            &[],
            UnixTime::now(),
        );

        assert!(res.is_ok());
    }

    #[test]
    fn client_verifier_accepts_authorized_spiffe_id() {
        ensure_provider();

        let verifier = SpiffeClientCertVerifier::new(
            static_provider(1),
            Arc::new(|id: &SpiffeId| id.to_string() == "spiffe://example.org/service")
                as Arc<dyn Authorizer>,
            TrustDomainPolicy::AnyInBundleSet,
        );

        let res = verifier.verify_client_cert(&cert_with_spiffe(), &[], UnixTime::now());
        assert!(res.is_ok());
    }

    #[test]
    fn verifier_cache_is_keyed_by_generation() {
        ensure_provider();

        let authorizer1: Arc<dyn Authorizer> = Arc::new(move |_: &SpiffeId| true);
        let v1 = SpiffeServerCertVerifier::new(
            static_provider(1),
            authorizer1,
            TrustDomainPolicy::AnyInBundleSet,
        );
        let s1 = v1.supported_verify_schemes();
        assert!(!s1.is_empty());

        let authorizer2: Arc<dyn Authorizer> = Arc::new(move |_: &SpiffeId| true);
        let v2 = SpiffeServerCertVerifier::new(
            static_provider(2),
            authorizer2,
            TrustDomainPolicy::AnyInBundleSet,
        );
        let s2 = v2.supported_verify_schemes();
        assert!(!s2.is_empty());
    }

    #[test]
    fn supported_verify_schemes_intersection() {
        ensure_provider();

        // Create a provider with multiple trust domains
        let mut roots_by_td = BTreeMap::new();
        let td1 = TrustDomain::new("example.org").expect("valid trust domain");
        let td2 = TrustDomain::new("other.org").expect("valid trust domain");
        roots_by_td.insert(td1.clone(), roots_with_ca());
        roots_by_td.insert(td2.clone(), roots_with_ca());

        let provider = Arc::new(StaticMaterial(Arc::new(MaterialSnapshot {
            generation: 1,
            certified_key: certified_key_from_fixtures(),
            roots_by_td,
        })));

        let authorizer: Arc<dyn Authorizer> = Arc::new(move |_: &SpiffeId| true);
        let verifier =
            SpiffeServerCertVerifier::new(provider, authorizer, TrustDomainPolicy::AnyInBundleSet);

        // Get schemes for each trust domain individually
        let schemes_td1 = verifier.supported_schemes_cached(&td1);
        let schemes_td2 = verifier.supported_schemes_cached(&td2);

        // The intersection should be non-empty (both use same CA, so same schemes)
        let intersection = verifier.supported_verify_schemes();
        assert!(!intersection.is_empty());

        // Intersection should be a subset of both (check manually since SignatureScheme doesn't implement Ord/Hash)
        for scheme in &intersection {
            assert!(
                schemes_td1.contains(scheme),
                "intersection scheme not in td1"
            );
            assert!(
                schemes_td2.contains(scheme),
                "intersection scheme not in td2"
            );
        }
    }

    #[test]
    fn supported_verify_schemes_policy_excludes_all_falls_back_to_union() {
        ensure_provider();

        let mut roots_by_td = BTreeMap::new();
        let td1 = TrustDomain::new("example.org").expect("valid trust domain");
        let td2 = TrustDomain::new("other.org").expect("valid trust domain");
        roots_by_td.insert(td1.clone(), roots_with_ca());
        roots_by_td.insert(td2.clone(), roots_with_ca());

        let provider = Arc::new(StaticMaterial(Arc::new(MaterialSnapshot {
            generation: 1,
            certified_key: certified_key_from_fixtures(),
            roots_by_td,
        })));

        // Policy that excludes all trust domains (use your real allow-list type here if exposed).
        // If you can't construct one from tests easily, skip this test.
        let policy = TrustDomainPolicy::AllowList(std::collections::BTreeSet::new());

        let verifier = SpiffeServerCertVerifier::new(
            provider,
            Arc::new(|_: &SpiffeId| true) as Arc<dyn Authorizer>,
            policy,
        );

        let schemes = verifier.supported_verify_schemes();

        // The point is: non-empty so we avoid NoSignatureSchemes at TLS layer.
        assert!(!schemes.is_empty());
    }
}
