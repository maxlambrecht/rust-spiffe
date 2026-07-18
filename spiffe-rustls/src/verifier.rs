//! rustls verifiers that authenticate with SPIFFE trust bundles and authorize by SPIFFE ID.
//!
//! For outbound TLS (client), the server certificate verifier validates the certificate chain
//! against the SPIFFE trust bundle and authorizes the peer by SPIFFE ID. It does **not** require
//! the TLS `server_name` to match DNS or IP subjectAltNames; peer identity comes from the SPIFFE ID
//! (URI SAN).
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
use std::collections::{HashMap, VecDeque};
use std::fmt::{self, Debug};
use std::sync::Arc;

#[cfg(feature = "parking-lot")]
use parking_lot::{Condvar, Mutex, MutexGuard};

#[cfg(not(feature = "parking-lot"))]
use std::sync::{Condvar, Mutex, MutexGuard};

// Unify lock() across std/parking_lot.
// - parking_lot never poisons => always Ok
// - std::sync::Mutex may poison => map to Err(())
#[cfg(feature = "parking-lot")]
#[expect(
    clippy::unnecessary_wraps,
    reason = "keep signature uniform with std (poisoning) implementation"
)]
fn lock_mutex<T>(m: &Mutex<T>) -> std::result::Result<MutexGuard<'_, T>, ()> {
    Ok(m.lock())
}

#[cfg(not(feature = "parking-lot"))]
fn lock_mutex<T>(m: &Mutex<T>) -> std::result::Result<MutexGuard<'_, T>, ()> {
    m.lock().map_err(|std::sync::PoisonError { .. }| ())
}

// Unify Condvar::wait() across std/parking_lot.
// Both consume the guard and return a guard.
#[cfg(feature = "parking-lot")]
#[expect(
    clippy::unnecessary_wraps,
    reason = "keep signature uniform with std (poisoning) implementation"
)]
fn condvar_wait<'a, T>(
    cv: &Condvar,
    mut guard: MutexGuard<'a, T>,
) -> std::result::Result<MutexGuard<'a, T>, ()> {
    cv.wait(&mut guard);
    Ok(guard)
}

#[cfg(not(feature = "parking-lot"))]
fn condvar_wait<'a, T>(
    cv: &Condvar,
    guard: MutexGuard<'a, T>,
) -> std::result::Result<MutexGuard<'a, T>, ()> {
    cv.wait(guard).map_err(|std::sync::PoisonError { .. }| ())
}

/// Cached result of parsing a peer certificate.
///
/// Both fields are pure functions of the certificate bytes, so cache hits avoid
/// re-parsing during the TLS handshake.
///
/// `leaf_check` is `Err(reason)` when the certificate is signing-capable and
/// therefore cannot be accepted as a peer X509-SVID leaf.
#[derive(Clone, Debug)]
struct CachedLeaf {
    spiffe_id: SpiffeId,
    leaf_check: std::result::Result<(), String>,
}

/// Bounded certificate parse cache with simple LRU eviction.
///
/// The cache is keyed by full certificate DER so cache matches are exact. Capacity
/// is small (64), so storing the DER is bounded and keeps the implementation simple.
///
/// Touch operations are O(capacity) which is acceptable at this size.
struct CertParseCache {
    entries: HashMap<Box<[u8]>, CachedLeaf>,
    order: VecDeque<Box<[u8]>>,
    capacity: usize,
}

impl CertParseCache {
    const CAPACITY: u8 = 64;

    fn new() -> Self {
        Self {
            entries: HashMap::with_capacity(Self::CAPACITY.into()),
            order: VecDeque::with_capacity(Self::CAPACITY.into()),
            capacity: Self::CAPACITY.into(),
        }
    }

    fn get(&mut self, key: &[u8]) -> Option<CachedLeaf> {
        let value = self.entries.get(key).cloned()?;

        // (O(n) remove; acceptable for small capacity)
        if let Some(pos) = self.order.iter().position(|k| k.as_ref() == key) {
            if let Some(k) = self.order.remove(pos) {
                self.order.push_back(k);
            }
        }

        Some(value)
    }

    fn insert(&mut self, key: &[u8], value: CachedLeaf) {
        if let Some(existing) = self.entries.get_mut(key) {
            *existing = value;
            self.touch(key);
            return;
        }

        if self.entries.len() >= self.capacity {
            self.evict_lru();
        }

        let owned: Box<[u8]> = Box::from(key);
        self.entries.insert(owned.clone(), value);
        self.order.push_back(owned);
    }

    fn touch(&mut self, key: &[u8]) {
        if let Some(pos) = self.order.iter().position(|k| k.as_ref() == key) {
            if let Some(k) = self.order.remove(pos) {
                self.order.push_back(k);
            }
        }
    }

    fn evict_lru(&mut self) {
        if let Some(oldest) = self.order.pop_front() {
            self.entries.remove(&oldest);
        }
    }
}

/// Extract the SPIFFE ID from the leaf certificate.
///
/// Does not use caching. For high-throughput scenarios, use the verifier's internal caching mechanism.
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
///
/// This is a convenience wrapper around `extract_spiffe_id_with_cache` for use in tests.
#[cfg(test)]
pub(crate) fn extract_spiffe_id(leaf: &CertificateDer<'_>) -> Result<SpiffeId> {
    extract_spiffe_id_with_cache(leaf, None)
}

/// Looks up, or parses and caches, the SPIFFE ID and leaf check for a certificate.
///
/// The cached result is keyed by full DER. On a cache hit, neither SPIFFE ID
/// extraction nor the leaf check re-parses the certificate.
fn lookup_or_parse_leaf(
    leaf: &CertificateDer<'_>,
    cache: Option<&Mutex<CertParseCache>>,
) -> Result<CachedLeaf> {
    let key = leaf.as_ref();

    if let Some(cache) = cache {
        if let Ok(mut guard) = lock_mutex(cache) {
            if let Some(cached) = guard.get(key) {
                return Ok(cached);
            }
        }
    }

    let spiffe_id = spiffe::cert::spiffe_id_from_der(leaf.as_ref()).map_err(|e| {
        use spiffe::cert::error::CertificateError as CE;
        match e {
            CE::MissingX509Extension(oid) if oid == oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME => {
                Error::MissingSpiffeId
            }
            CE::MissingSpiffeId => Error::MissingSpiffeId,
            CE::MultipleSpiffeIds => Error::MultipleSpiffeIds,
            _ => Error::CertParse(e.to_string()),
        }
    })?;

    let cached = CachedLeaf {
        spiffe_id,
        leaf_check: leaf_constraint_check(leaf),
    };

    if let Some(cache) = cache {
        if let Ok(mut guard) = lock_mutex(cache) {
            guard.insert(key, cached.clone());
        }
    }

    Ok(cached)
}

/// Extracts the SPIFFE ID from the leaf certificate, using the parse cache when provided.
///
/// This helper is for TLS signature-verification callbacks, which only need the
/// trust domain and run after `verify_*_cert` has enforced the leaf check.
fn extract_spiffe_id_with_cache(
    leaf: &CertificateDer<'_>,
    cache: Option<&Mutex<CertParseCache>>,
) -> Result<SpiffeId> {
    Ok(lookup_or_parse_leaf(leaf, cache)?.spiffe_id)
}

/// Rejects certificates that must not be used as X509-SVID leaf identities.
///
/// **Specification:** X509-SVID section 5.2 requires leaf validation to reject
/// signing-capable certificates (`cA=true`, `keyCertSign`, or `cRLSign`).
/// Section 4.3 requires leaf SVIDs to carry a key usage extension with
/// `digitalSignature` set (and marked critical at issuance); section 5.2 does
/// not restate that requirement as a validation MUST.
///
/// **Enforced here:** signing-capable certificates are rejected per section 5.2.
/// The key usage extension must be present and must set `digitalSignature`; this
/// aligns peer acceptance with section 4.3 certificate constraints even though
/// section 5.2 does not explicitly require checking them at validation time. The
/// critical bit on the extension is not checked here.
///
/// Returns `Ok(())` for a valid leaf, or `Err(reason)` describing the violation
/// (or a parse failure, which fails closed).
fn leaf_constraint_check(leaf: &CertificateDer<'_>) -> std::result::Result<(), String> {
    let (_, cert) =
        x509_parser::parse_x509_certificate(leaf.as_ref()).map_err(|e| e.to_string())?;

    if let Some(bc) = cert.basic_constraints().map_err(|e| e.to_string())? {
        if bc.value.ca {
            return Err("basic constraints CA is set to true (signing certificate)".into());
        }
    }

    match cert.key_usage().map_err(|e| e.to_string())? {
        Some(ku) => {
            if ku.value.key_cert_sign() {
                return Err("keyCertSign key usage is set".into());
            }
            if ku.value.crl_sign() {
                return Err("cRLSign key usage is set".into());
            }
            if !ku.value.digital_signature() {
                return Err("digitalSignature key usage is not set".into());
            }
        }
        None => return Err("key usage extension is missing".into()),
    }

    Ok(())
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

/// Maximum number of entries in the verifier cache.
///
/// Federated environments typically involve 2-5 trust domains. A capacity of 8
/// accommodates common deployments while bounding memory usage. When the cache
/// is full, the oldest entry (FIFO) is evicted.
const VERIFIER_CACHE_CAPACITY: usize = 8;

/// Cache key for verifiers: (generation, `trust_domain`)
type VerifierCacheKey = (u64, spiffe::TrustDomain);

#[derive(Clone)]
struct ServerVerifierCacheValue {
    verifier: Arc<dyn rustls::client::danger::ServerCertVerifier>,
    roots: Arc<rustls::RootCertStore>,
    supported_algs: rustls::crypto::WebPkiSupportedAlgorithms,
    schemes: Vec<SignatureScheme>,
}

enum ServerBuildState {
    Empty,
    Building,
    Ready(ServerVerifierCacheValue),
}

struct ServerBuildCell {
    state: Mutex<ServerBuildState>,
    cv: Condvar,
}

impl ServerBuildCell {
    const fn new() -> Self {
        Self {
            state: Mutex::new(ServerBuildState::Empty),
            cv: Condvar::new(),
        }
    }
}

/// RAII guard held by the single builder for a [`ServerBuildCell`] while it
/// runs the (lock-free) build.
///
/// Unless [`disarm`](Self::disarm) is called after publishing `Ready`,
/// dropping this guard reverts the cell to `Empty` and wakes any waiters.
/// This covers both an early `Err` return *and* a panic unwinding out of the
/// build call, so a single failed or panicking build can never leave the
/// cell wedged in `Building` with other threads blocked on the condvar
/// forever.
struct ServerBuildGuard<'a> {
    cell: &'a ServerBuildCell,
    armed: bool,
}

impl<'a> ServerBuildGuard<'a> {
    const fn new(cell: &'a ServerBuildCell) -> Self {
        Self { cell, armed: true }
    }

    /// Call after successfully publishing `Ready`, so drop does not revert it.
    const fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ServerBuildGuard<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        // Best-effort: if the state mutex is poisoned we can't safely reset
        // it, but still notify so waiters re-check and observe the poison
        // (fail fast) instead of blocking on the condvar forever.
        if let Ok(mut g) = lock_mutex(&self.cell.state) {
            *g = ServerBuildState::Empty;
        }
        self.cell.cv.notify_all();
    }
}

#[derive(Clone)]
struct ServerVerifierCache {
    key: VerifierCacheKey,
    cell: Arc<ServerBuildCell>,
}

#[derive(Clone)]
struct ClientVerifierCacheValue {
    verifier: Arc<dyn rustls::server::danger::ClientCertVerifier>,
    schemes: Vec<SignatureScheme>,
}

enum ClientBuildState {
    Empty,
    Building,
    Ready(ClientVerifierCacheValue),
}

struct ClientBuildCell {
    state: Mutex<ClientBuildState>,
    cv: Condvar,
}

impl ClientBuildCell {
    const fn new() -> Self {
        Self {
            state: Mutex::new(ClientBuildState::Empty),
            cv: Condvar::new(),
        }
    }
}

/// RAII guard held by the single builder for a [`ClientBuildCell`]; see
/// [`ServerBuildGuard`] for the rationale (panic/early-return safety).
struct ClientBuildGuard<'a> {
    cell: &'a ClientBuildCell,
    armed: bool,
}

impl<'a> ClientBuildGuard<'a> {
    const fn new(cell: &'a ClientBuildCell) -> Self {
        Self { cell, armed: true }
    }

    /// Call after successfully publishing `Ready`, so drop does not revert it.
    const fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ClientBuildGuard<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Ok(mut g) = lock_mutex(&self.cell.state) {
            *g = ClientBuildState::Empty;
        }
        self.cell.cv.notify_all();
    }
}

#[derive(Clone)]
struct ClientVerifierCache {
    key: VerifierCacheKey,
    cell: Arc<ClientBuildCell>,
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

fn build_server_cache_value(roots: Arc<rustls::RootCertStore>) -> Result<ServerVerifierCacheValue> {
    let verifier = build_server_verifier(Arc::clone(&roots))?;
    let schemes = verifier.supported_verify_schemes();
    let supported_algs = rustls::crypto::CryptoProvider::get_default()
        .ok_or_else(|| Error::VerifierBuilder("rustls crypto provider is not installed".into()))?
        .signature_verification_algorithms;

    Ok(ServerVerifierCacheValue {
        verifier,
        roots,
        supported_algs,
        schemes,
    })
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

/// Returns `true` if `err` is a TLS server-name mismatch from the webpki name check.
///
/// Kept for regression tests around the old fail-open risk: SPIFFE server verification must not
/// decide whether chain validation succeeded by classifying the error from a combined
/// chain-and-name verifier. SPIFFE peer authentication uses the configured trust bundle and the
/// SPIFFE ID (URI SAN), not DNS/IP SAN matching to the dial target.
#[cfg(test)]
const fn webpki_tls_hostname_mismatch(err: &rustls::Error) -> bool {
    matches!(
        err,
        rustls::Error::InvalidCertificate(
            rustls::CertificateError::NotValidForName
                | rustls::CertificateError::NotValidForNameContext { .. }
        )
    )
}

// ------------ Server verifier (client side) ------------

#[derive(Clone)]
pub(crate) struct SpiffeServerCertVerifier {
    provider: Arc<dyn MaterialProvider>,
    authorizer: Arc<dyn Authorizer>,
    policy: TrustDomainPolicy,
    cache: Arc<Mutex<VecDeque<ServerVerifierCache>>>,
    parse_cache: Arc<Mutex<CertParseCache>>,
    last_logged_gen: Arc<Mutex<Option<u64>>>,
}

impl SpiffeServerCertVerifier {
    pub(crate) fn new(
        provider: Arc<dyn MaterialProvider>,
        authorizer: impl Authorizer,
        policy: TrustDomainPolicy,
    ) -> Self {
        Self {
            provider,
            authorizer: Arc::new(authorizer),
            policy,
            cache: Arc::new(Mutex::new(VecDeque::with_capacity(VERIFIER_CACHE_CAPACITY))),
            parse_cache: Arc::new(Mutex::new(CertParseCache::new())),
            last_logged_gen: Arc::new(Mutex::new(None)),
        }
    }

    /// Gets or builds a verifier for the given trust domain.
    fn get_or_build_inner(
        &self,
        trust_domain: &spiffe::TrustDomain,
    ) -> Result<ServerVerifierCacheValue> {
        let snap = self.provider.current_material();
        let r#gen = snap.generation;

        let td = trust_domain.clone();

        if !self.policy.allows(&td) {
            return Err(Error::TrustDomainNotAllowed(td));
        }

        let roots = match snap.roots_by_td.get(&td) {
            Some(roots) => Arc::clone(roots),
            None => return Err(Error::NoBundle(td)),
        };

        let cache_key = (r#gen, td);

        // Select (or create) the per-key single-flight cell under the outer cache mutex.
        let cell: Arc<ServerBuildCell> = {
            let mut guard = lock_mutex(&self.cache)
                .map_err(|()| Error::Internal("server verifier cache mutex poisoned".into()))?;

            if let Some(entry) = guard.iter().find(|e| e.key == cache_key) {
                Arc::clone(&entry.cell)
            } else {
                let cell = Arc::new(ServerBuildCell::new());
                if guard.len() >= VERIFIER_CACHE_CAPACITY {
                    guard.pop_front(); // FIFO eviction of oldest entry
                }
                guard.push_back(ServerVerifierCache {
                    key: cache_key,
                    cell: Arc::clone(&cell),
                });
                cell
            }
        };

        loop {
            let mut guard = lock_mutex(&cell.state)
                .map_err(|()| Error::Internal("server verifier cache mutex poisoned".into()))?;

            match &*guard {
                ServerBuildState::Ready(v) => return Ok(v.clone()),

                ServerBuildState::Empty => {
                    // Become the single builder (no race window).
                    *guard = ServerBuildState::Building;
                    drop(guard);

                    // Reverts the cell to `Empty` and wakes waiters unless disarmed
                    // below; covers both `?` below and an unexpected panic from the
                    // (lock-free) build call.
                    let mut build_guard = ServerBuildGuard::new(&cell);

                    // Build without holding any locks.
                    let value = build_server_cache_value(Arc::clone(&roots))?;

                    // Publish success and wake waiters.
                    let mut g = lock_mutex(&cell.state).map_err(|()| {
                        Error::Internal("server verifier cache mutex poisoned".into())
                    })?;
                    let cached = value.clone();
                    *g = ServerBuildState::Ready(value);
                    drop(g);
                    build_guard.disarm();
                    cell.cv.notify_all();
                    return Ok(cached);
                }

                ServerBuildState::Building => {
                    // Wait for builder to publish Ready or revert to Empty on failure.
                    let g = condvar_wait(&cell.cv, guard).map_err(|()| {
                        Error::Internal("server verifier cache mutex poisoned".into())
                    })?;
                    drop(g);
                }
            }
        }
    }

    fn supported_schemes_cached(&self, trust_domain: &spiffe::TrustDomain) -> Vec<SignatureScheme> {
        let cell = match lock_mutex(&self.cache) {
            Ok(guard) => guard
                .iter()
                .find(|e| e.key.1 == *trust_domain)
                .map(|e| Arc::clone(&e.cell)),
            Err(_e) => {
                error!("server verifier cache mutex poisoned; returning empty schemes (handshake will fail)");
                return Vec::new();
            }
        };

        if let Some(cell) = cell {
            if let Ok(guard) = lock_mutex(&cell.state) {
                if let ServerBuildState::Ready(v) = &*guard {
                    return v.schemes.clone();
                }
            }
        }

        match self.get_or_build_inner(trust_domain) {
            Ok(v) => v.schemes,
            Err(e) => {
                debug!(
                "failed to build server verifier for trust domain {trust_domain}: {e}; returning empty schemes (handshake will fail)");
                Vec::new()
            }
        }
    }
}

fn verify_server_cert_chain(
    verifier: &ServerVerifierCacheValue,
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    now: UnixTime,
) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
    let cert = rustls::server::ParsedCertificate::try_from(end_entity)?;

    rustls::client::verify_server_cert_signed_by_trust_anchor(
        &cert,
        &verifier.roots,
        intermediates,
        now,
        verifier.supported_algs.all,
    )?;

    Ok(rustls::client::danger::ServerCertVerified::assertion())
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
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // Step 1: Extract SPIFFE ID and leaf-constraint check from the certificate (using cache).
        // Extraction is safe because the SPIFFE ID is only used to select the trust domain's root
        // certificate bundle. Cryptographic verification (signature, chain, expiration) is still
        // enforced by rustls using the selected roots. Policy can further restrict which trust
        // domains are allowed.
        let CachedLeaf {
            spiffe_id,
            leaf_check,
        } = lookup_or_parse_leaf(end_entity, Some(&self.parse_cache)).map_err(other_err)?;

        // Step 2: Derive trust domain from SPIFFE ID
        let trust_domain = spiffe_id.trust_domain();

        // Step 3: Get or build verifier for this trust domain
        let verifier = self.get_or_build_inner(trust_domain).map_err(other_err)?;

        // Step 4: Reject signing-capable certificates as peer leaf identities.
        if let Err(reason) = leaf_check {
            return Err(other_err(Error::InvalidLeaf(reason)));
        }

        // Step 5: Verify certificate chain.
        //
        // For SPIFFE server authentication, DNS/IP SAN matching is intentionally not part of the
        // identity check. Use rustls's chain-only webpki helper so path validation is explicit and
        // cannot be masked by any future change in rustls name-check error ordering.
        let ok = verify_server_cert_chain(&verifier, end_entity, intermediates, now)?;

        // Step 6: Apply authorization (only after cryptographic verification succeeds)
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
        // Extract trust domain from cert for signature verification
        let spiffe_id =
            extract_spiffe_id_with_cache(cert, Some(&self.parse_cache)).map_err(other_err)?;
        let trust_domain = spiffe_id.trust_domain();
        let inner = self.get_or_build_inner(trust_domain).map_err(other_err)?;
        inner.verifier.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // Extract trust domain from cert for signature verification
        let spiffe_id =
            extract_spiffe_id_with_cache(cert, Some(&self.parse_cache)).map_err(other_err)?;
        let trust_domain = spiffe_id.trust_domain();
        let inner = self.get_or_build_inner(trust_domain).map_err(other_err)?;
        inner.verifier.verify_tls13_signature(message, cert, dss)
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
        )
    }
}

// ------------ Client verifier (server side) ------------

#[derive(Clone)]
pub(crate) struct SpiffeClientCertVerifier {
    provider: Arc<dyn MaterialProvider>,
    authorizer: Arc<dyn Authorizer>,
    policy: TrustDomainPolicy,
    cache: Arc<Mutex<VecDeque<ClientVerifierCache>>>,
    parse_cache: Arc<Mutex<CertParseCache>>,
    last_logged_gen: Arc<Mutex<Option<u64>>>,
}

impl SpiffeClientCertVerifier {
    pub(crate) fn new(
        provider: Arc<dyn MaterialProvider>,
        authorizer: impl Authorizer,
        policy: TrustDomainPolicy,
    ) -> Self {
        Self {
            provider,
            authorizer: Arc::new(authorizer),
            policy,
            cache: Arc::new(Mutex::new(VecDeque::with_capacity(VERIFIER_CACHE_CAPACITY))),
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
        let r#gen = snap.generation;

        let td = trust_domain.clone();

        if !self.policy.allows(&td) {
            return Err(Error::TrustDomainNotAllowed(td));
        }

        let roots = match snap.roots_by_td.get(&td) {
            Some(roots) => Arc::clone(roots),
            None => return Err(Error::NoBundle(td)),
        };

        let cache_key = (r#gen, td);

        let cell: Arc<ClientBuildCell> = {
            let mut guard = lock_mutex(&self.cache)
                .map_err(|()| Error::Internal("client verifier cache mutex poisoned".into()))?;

            if let Some(entry) = guard.iter().find(|e| e.key == cache_key) {
                Arc::clone(&entry.cell)
            } else {
                let cell = Arc::new(ClientBuildCell::new());
                if guard.len() >= VERIFIER_CACHE_CAPACITY {
                    guard.pop_front(); // FIFO eviction of oldest entry
                }
                guard.push_back(ClientVerifierCache {
                    key: cache_key,
                    cell: Arc::clone(&cell),
                });
                cell
            }
        };

        loop {
            let mut guard = lock_mutex(&cell.state)
                .map_err(|()| Error::Internal("client verifier cache mutex poisoned".into()))?;

            match &*guard {
                ClientBuildState::Ready(v) => return Ok(Arc::clone(&v.verifier)),

                ClientBuildState::Empty => {
                    // Become the single builder (no race window).
                    *guard = ClientBuildState::Building;
                    drop(guard);

                    // Reverts the cell to `Empty` and wakes waiters unless disarmed
                    // below; covers both `?` below and an unexpected panic from the
                    // (lock-free) build call.
                    let mut build_guard = ClientBuildGuard::new(&cell);

                    let verifier = build_client_verifier(roots)?;

                    let schemes = verifier.supported_verify_schemes();
                    let value = ClientVerifierCacheValue { verifier, schemes };

                    let mut g = lock_mutex(&cell.state).map_err(|()| {
                        Error::Internal("client verifier cache mutex poisoned".into())
                    })?;
                    let verifier = Arc::clone(&value.verifier);
                    *g = ClientBuildState::Ready(value);
                    drop(g);
                    build_guard.disarm();
                    cell.cv.notify_all();
                    return Ok(verifier);
                }

                ClientBuildState::Building => {
                    let g = condvar_wait(&cell.cv, guard).map_err(|()| {
                        Error::Internal("client verifier cache mutex poisoned".into())
                    })?;
                    drop(g);
                }
            }
        }
    }

    fn supported_schemes_cached(&self, trust_domain: &spiffe::TrustDomain) -> Vec<SignatureScheme> {
        let cell = match lock_mutex(&self.cache) {
            Ok(guard) => guard
                .iter()
                .find(|e| e.key.1 == *trust_domain)
                .map(|e| Arc::clone(&e.cell)),
            Err(_e) => {
                error!("client verifier cache mutex poisoned; returning empty schemes (handshake will fail)");
                return Vec::new();
            }
        };

        if let Some(cell) = cell {
            if let Ok(guard) = lock_mutex(&cell.state) {
                if let ClientBuildState::Ready(v) = &*guard {
                    return v.schemes.clone();
                }
            }
        }

        match self.get_or_build_inner(trust_domain) {
            Ok(v) => v.supported_verify_schemes(),
            Err(e) => {
                debug!(
                "failed to build client verifier for trust domain {trust_domain}: {e}; returning empty schemes (handshake will fail)");
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
        // Step 1: Extract SPIFFE ID and leaf-constraint check from the certificate (using cache).
        // Extraction is safe because the SPIFFE ID is only used to select the trust domain's root
        // certificate bundle. Cryptographic verification (signature, chain, expiration) is still
        // enforced by rustls using the selected roots. Policy can further restrict which trust
        // domains are allowed.
        let CachedLeaf {
            spiffe_id,
            leaf_check,
        } = lookup_or_parse_leaf(end_entity, Some(&self.parse_cache)).map_err(other_err)?;

        // Step 2: Derive trust domain from SPIFFE ID
        let trust_domain = spiffe_id.trust_domain();

        // Step 3: Get or build verifier for this trust domain
        let inner = self.get_or_build_inner(trust_domain).map_err(other_err)?;

        // Step 4: Reject signing-capable certificates as peer leaf identities.
        if let Err(reason) = leaf_check {
            return Err(other_err(Error::InvalidLeaf(reason)));
        }

        // Step 5: Verify certificate chain cryptographically
        let ok = inner.verify_client_cert(end_entity, intermediates, now)?;

        // Step 6: Apply authorization (only after cryptographic verification succeeds)
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
        // Extract trust domain from cert for signature verification
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
        // Extract trust domain from cert for signature verification
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
/// # Empty-policy case
/// If policy excludes every trust domain in the snapshot, this returns an empty
/// scheme list instead of advertising schemes from disallowed trust domains. This
/// preserves fail-closed semantics, but it also means the TLS layer may fail
/// before certificate verification can report `TrustDomainNotAllowed`.
fn advertised_verify_schemes(
    label: &str,
    r#gen: u64,
    last_logged_gen: &Mutex<Option<u64>>,
    snap: &MaterialSnapshot,
    policy: &TrustDomainPolicy,
    mut per_td_schemes: impl FnMut(&spiffe::TrustDomain) -> Vec<SignatureScheme>,
) -> Vec<SignatureScheme> {
    // Collect schemes for trust domains allowed by policy.
    let mut scheme_sets: Vec<Vec<SignatureScheme>> = Vec::new();
    let mut allowed_count = 0usize;

    for td in snap.roots_by_td.keys() {
        if !policy.allows(td) {
            continue;
        }

        allowed_count += 1;
        let schemes = per_td_schemes(td);
        if !schemes.is_empty() {
            scheme_sets.push(schemes);
        }
    }

    // Normal case: intersection across allowed trust domains.
    if let Some(first) = scheme_sets.first() {
        return first
            .iter()
            .filter(|scheme| scheme_sets.iter().skip(1).all(|set| set.contains(scheme)))
            .copied()
            .collect();
    }

    if allowed_count > 0 {
        return Vec::new();
    }

    // Policy excluded all trust domains: return empty schemes rather than exposing
    // schemes from disallowed trust domains.
    let should_log = match lock_mutex(last_logged_gen) {
        Ok(mut guard) => {
            if guard.as_ref() == Some(&r#gen) {
                false
            } else {
                *guard = Some(r#gen);
                true
            }
        }
        Err(_e) => true, // poisoned mutex: skip "log once" optimization
    };

    if should_log {
        let snapshot_tds = join_trust_domains(snap.roots_by_td.keys());
        error!(
            "{label}: trust domain policy excludes all trust domains in current bundle set \
            (snapshot trust domains: {snapshot_tds}); returning empty schemes (handshake will fail closed)");
    }

    Vec::new()
}

fn join_trust_domains<'a, I: Iterator<Item = &'a spiffe::TrustDomain>>(tds: I) -> String {
    tds.map(ToString::to_string).collect::<Vec<_>>().join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::client::danger::ServerCertVerifier as _;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::server::danger::ClientCertVerifier as _;
    use rustls::RootCertStore;
    use spiffe::TrustDomain;
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::OnceLock;

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

    /// Leaf certificate with only a SPIFFE URI in SAN (typical SPIRE default; no DNS SAN).
    fn fixture_spiffe_leaf_uri_only_der() -> &'static [u8] {
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/spiffe_leaf_uri_only.der"
        ))
    }

    fn fixture_no_spiffe_leaf_der() -> &'static [u8] {
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/no_spiffe_leaf.der"
        ))
    }

    /// Self-signed signing (CA) certificate that carries a SPIFFE URI SAN
    /// (`cA=true`, `keyCertSign`/`cRLSign` set). Such a certificate must never be
    /// accepted as a peer leaf identity, per X509-SVID spec section 5.2.
    fn fixture_ca_with_spiffe_signing_der() -> &'static [u8] {
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/ca_with_spiffe_signing.der"
        ))
    }

    fn cert_ca_with_spiffe_signing() -> CertificateDer<'static> {
        CertificateDer::from(fixture_ca_with_spiffe_signing_der().to_vec())
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

    fn cert_with_spiffe_uri_only() -> CertificateDer<'static> {
        CertificateDer::from(fixture_spiffe_leaf_uri_only_der().to_vec())
    }

    fn cert_without_spiffe() -> CertificateDer<'static> {
        CertificateDer::from(fixture_no_spiffe_leaf_der().to_vec())
    }

    /// Leaf with a SPIFFE URI SAN but no key usage extension at all.
    fn fixture_spiffe_leaf_no_key_usage_der() -> &'static [u8] {
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/spiffe_leaf_no_key_usage.der"
        ))
    }

    /// Leaf with a SPIFFE URI SAN and a key usage extension that does not set
    /// `digitalSignature` (only `keyEncipherment`).
    fn fixture_spiffe_leaf_no_digital_signature_der() -> &'static [u8] {
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/spiffe_leaf_no_digital_signature.der"
        ))
    }

    fn cert_with_spiffe_no_key_usage() -> CertificateDer<'static> {
        CertificateDer::from(fixture_spiffe_leaf_no_key_usage_der().to_vec())
    }

    fn cert_with_spiffe_no_digital_signature() -> CertificateDer<'static> {
        CertificateDer::from(fixture_spiffe_leaf_no_digital_signature_der().to_vec())
    }

    fn roots_with_ca() -> Arc<RootCertStore> {
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(fixture_ca_der().to_vec()))
            .expect("fixture CA must parse");
        Arc::new(roots)
    }

    fn fixture_ca_uri_only_der() -> &'static [u8] {
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/ca_uri_only.der"
        ))
    }

    fn roots_with_ca_uri_only() -> Arc<RootCertStore> {
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(fixture_ca_uri_only_der().to_vec()))
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
            Arc::clone(&self.0)
        }
    }

    fn static_provider_single_td(generation: u64, td: &str) -> Arc<dyn MaterialProvider> {
        let mut roots_by_td = BTreeMap::new();
        let td = TrustDomain::new(td).expect("valid trust domain");
        roots_by_td.insert(td, roots_with_ca());

        Arc::new(StaticMaterial(Arc::new(MaterialSnapshot {
            generation,
            certified_key: certified_key_from_fixtures(),
            roots_by_td,
        })))
    }

    fn static_provider_example_org(generation: u64) -> Arc<dyn MaterialProvider> {
        static_provider_single_td(generation, "example.org")
    }

    fn server_name_example_org() -> ServerName<'static> {
        ServerName::try_from("example.org").unwrap()
    }

    fn server_name_localhost() -> ServerName<'static> {
        ServerName::try_from("localhost").unwrap()
    }

    fn static_provider_uri_only_example_org(generation: u64) -> Arc<dyn MaterialProvider> {
        let mut roots_by_td = BTreeMap::new();
        let td = TrustDomain::new("example.org").expect("valid trust domain");
        roots_by_td.insert(td, roots_with_ca_uri_only());

        Arc::new(StaticMaterial(Arc::new(MaterialSnapshot {
            generation,
            certified_key: certified_key_from_fixtures(),
            roots_by_td,
        })))
    }

    fn assert_other_downcasts_to_error(err: &rustls::Error) -> &Error {
        match err {
            rustls::Error::Other(other) => {
                let dyn_err: &(dyn std::error::Error + Send + Sync + 'static) = other.0.as_ref();

                dyn_err
                    .downcast_ref::<Error>()
                    .expect("rustls::Error::Other must wrap crate::Error in these tests")
            }
            _ => panic!("expected rustls::Error::Other(..), got: {err:?}"),
        }
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
    fn leaf_constraint_check_accepts_leaf_certificate() {
        leaf_constraint_check(&cert_with_spiffe()).unwrap();
        leaf_constraint_check(&cert_with_spiffe_uri_only()).unwrap();
    }

    #[test]
    fn leaf_constraint_check_rejects_ca_certificate() {
        // ca.der has CA:TRUE and keyCertSign/cRLSign set.
        leaf_constraint_check(&CertificateDer::from(fixture_ca_der().to_vec())).unwrap_err();
    }

    #[test]
    fn leaf_constraint_check_rejects_signing_cert_with_spiffe_id() {
        leaf_constraint_check(&cert_ca_with_spiffe_signing()).unwrap_err();
    }

    #[test]
    fn leaf_constraint_check_rejects_leaf_without_key_usage() {
        // A leaf SVID must carry a key usage extension with digitalSignature set;
        // a leaf with no key usage extension must be rejected.
        leaf_constraint_check(&cert_with_spiffe_no_key_usage()).unwrap_err();
    }

    #[test]
    fn leaf_constraint_check_rejects_leaf_without_digital_signature() {
        // A leaf with key usage present but digitalSignature unset must be rejected.
        leaf_constraint_check(&cert_with_spiffe_no_digital_signature()).unwrap_err();
    }

    /// A signing-capable certificate that carries a SPIFFE ID must be rejected
    /// before chain validation or authorization can accept it as a peer identity.
    #[test]
    fn server_verifier_rejects_signing_cert_presented_as_leaf() {
        ensure_provider();

        let verifier = SpiffeServerCertVerifier::new(
            static_provider_example_org(1),
            |_peer: &SpiffeId| true,
            TrustDomainPolicy::AnyInBundleSet,
        );

        let err = verifier
            .verify_server_cert(
                &cert_ca_with_spiffe_signing(),
                &[],
                &server_name_example_org(),
                &[],
                UnixTime::now(),
            )
            .unwrap_err();

        let e = assert_other_downcasts_to_error(&err);
        assert!(matches!(e, Error::InvalidLeaf(_)), "got {e:?}");
    }

    #[test]
    fn client_verifier_rejects_signing_cert_presented_as_leaf() {
        ensure_provider();

        let verifier = SpiffeClientCertVerifier::new(
            static_provider_example_org(1),
            |_peer: &SpiffeId| true,
            TrustDomainPolicy::AnyInBundleSet,
        );

        let err = verifier
            .verify_client_cert(&cert_ca_with_spiffe_signing(), &[], UnixTime::now())
            .unwrap_err();

        let e = assert_other_downcasts_to_error(&err);
        assert!(matches!(e, Error::InvalidLeaf(_)), "got {e:?}");
    }

    #[test]
    fn server_verifier_rejects_unauthorized_spiffe_id() {
        ensure_provider();

        let verifier = SpiffeServerCertVerifier::new(
            static_provider_example_org(1),
            |_peer: &SpiffeId| false,
            TrustDomainPolicy::AnyInBundleSet,
        );

        let err = verifier
            .verify_server_cert(
                &cert_with_spiffe(),
                &[],
                &server_name_example_org(),
                &[],
                UnixTime::now(),
            )
            .unwrap_err();

        let e = assert_other_downcasts_to_error(&err);
        assert!(matches!(e, Error::UnauthorizedSpiffeId(_)));
    }

    #[test]
    fn client_verifier_rejects_unauthorized_spiffe_id() {
        ensure_provider();

        let verifier = SpiffeClientCertVerifier::new(
            static_provider_example_org(1),
            |_peer: &SpiffeId| false,
            TrustDomainPolicy::AnyInBundleSet,
        );

        let err = verifier
            .verify_client_cert(&cert_with_spiffe(), &[], UnixTime::now())
            .unwrap_err();

        let e = assert_other_downcasts_to_error(&err);
        assert!(matches!(e, Error::UnauthorizedSpiffeId(_)));
    }

    #[test]
    fn server_verifier_accepts_authorized_spiffe_id() {
        ensure_provider();

        let verifier = SpiffeServerCertVerifier::new(
            static_provider_example_org(1),
            |id: &SpiffeId| id.to_string() == "spiffe://example.org/service",
            TrustDomainPolicy::AnyInBundleSet,
        );

        let _: rustls::client::danger::ServerCertVerified = verifier
            .verify_server_cert(
                &cert_with_spiffe(),
                &[],
                &server_name_example_org(),
                &[],
                UnixTime::now(),
            )
            .unwrap();
    }

    /// URI-only SVID (no DNS SAN) with `server_name` `localhost`, as when dialing a SPIRE workload
    /// on loopback. Chain validation must succeed; TLS hostname checks must not apply.
    #[test]
    fn server_verifier_accepts_uri_only_svid_when_server_name_is_localhost() {
        ensure_provider();

        let verifier = SpiffeServerCertVerifier::new(
            static_provider_uri_only_example_org(1),
            |id: &SpiffeId| id.to_string() == "spiffe://example.org/service",
            TrustDomainPolicy::AnyInBundleSet,
        );

        let _: rustls::client::danger::ServerCertVerified = verifier
            .verify_server_cert(
                &cert_with_spiffe_uri_only(),
                &[],
                &server_name_localhost(),
                &[],
                UnixTime::now(),
            )
            .unwrap();
    }

    #[test]
    fn webpki_combined_verifier_reports_name_mismatch_for_valid_uri_only_svid() {
        ensure_provider();

        let verifier = build_server_verifier(roots_with_ca_uri_only()).unwrap();
        let err = verifier
            .verify_server_cert(
                &cert_with_spiffe_uri_only(),
                &[],
                &server_name_localhost(),
                &[],
                UnixTime::now(),
            )
            .unwrap_err();

        assert!(
            webpki_tls_hostname_mismatch(&err),
            "fixture must exercise rustls DNS/IP name mismatch handling: {err:?}"
        );
    }

    /// Wrong trust anchor: chain validation fails inside rustls before hostname checks. We must not
    /// treat that as a hostname-only case or accept the certificate.
    #[test]
    fn server_verifier_rejects_mismatched_trust_anchor_with_uri_only_leaf_and_localhost() {
        ensure_provider();

        // `cert_with_spiffe_uri_only` chains to `ca_uri_only.der`; provider supplies `ca.der` only.
        let verifier = SpiffeServerCertVerifier::new(
            static_provider_example_org(1),
            |_peer: &SpiffeId| true,
            TrustDomainPolicy::AnyInBundleSet,
        );

        let err = verifier
            .verify_server_cert(
                &cert_with_spiffe_uri_only(),
                &[],
                &server_name_localhost(),
                &[],
                UnixTime::now(),
            )
            .unwrap_err();

        assert!(
            !webpki_tls_hostname_mismatch(&err),
            "unknown issuer must not be classified as hostname mismatch: {err:?}"
        );
        assert!(
            matches!(
                err,
                rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer)
            ),
            "expected UnknownIssuer, got {err:?}"
        );
    }

    /// Trust-domain confusion: a peer leaf whose SPIFFE ID claims trust domain A
    /// must be verified against trust domain A's roots, not against any root that
    /// happens to be present in the bundle set.
    ///
    /// Here `cert_with_spiffe` claims `spiffe://example.org/service` and is signed
    /// by `ca.der`. The bundle set maps `example.org` to an unrelated CA
    /// (`ca_uri_only.der`) and maps a second trust domain (`other.org`) to the real
    /// signer (`ca.der`). If the verifier selected roots by trust domain, chain
    /// validation must fail with `UnknownIssuer`; if it instead tried every trusted
    /// root, it would wrongly succeed.
    #[test]
    fn server_verifier_rejects_trust_domain_confusion_across_bundle_set() {
        ensure_provider();

        // example.org -> wrong CA (did not sign the leaf); other.org -> real signer.
        let mut roots_by_td = BTreeMap::new();
        roots_by_td.insert(
            TrustDomain::new("example.org").unwrap(),
            roots_with_ca_uri_only(),
        );
        roots_by_td.insert(TrustDomain::new("other.org").unwrap(), roots_with_ca());

        let provider: Arc<dyn MaterialProvider> =
            Arc::new(StaticMaterial(Arc::new(MaterialSnapshot {
                generation: 1,
                certified_key: certified_key_from_fixtures(),
                roots_by_td,
            })));

        // Authorizer accepts the claimed ID so the only possible rejection comes
        // from trust-domain-scoped root selection / chain validation.
        let verifier = SpiffeServerCertVerifier::new(
            provider,
            |_peer: &SpiffeId| true,
            TrustDomainPolicy::AnyInBundleSet,
        );

        let err = verifier
            .verify_server_cert(
                &cert_with_spiffe(),
                &[],
                &server_name_example_org(),
                &[],
                UnixTime::now(),
            )
            .unwrap_err();

        assert!(
            matches!(
                err,
                rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer)
            ),
            "leaf signed by other.org's CA must not validate against example.org's roots, \
             even though that CA is present in the bundle set; got {err:?}"
        );
    }

    #[test]
    fn server_verifier_does_not_authorize_when_chain_invalid_even_if_name_mismatch() {
        ensure_provider();

        // `cert_with_spiffe_uri_only` has no DNS/IP SAN for localhost and chains to
        // `ca_uri_only.der`; provider supplies `ca.der` only. Even if a combined verifier ever
        // reported the name mismatch first, SPIFFE authorization must not run for this chain.
        let authorize_calls = Arc::new(AtomicUsize::new(0));
        let calls = Arc::clone(&authorize_calls);
        let verifier = SpiffeServerCertVerifier::new(
            static_provider_example_org(1),
            move |_peer: &SpiffeId| {
                calls.fetch_add(1, Ordering::SeqCst);
                true
            },
            TrustDomainPolicy::AnyInBundleSet,
        );

        let err = verifier
            .verify_server_cert(
                &cert_with_spiffe_uri_only(),
                &[],
                &server_name_localhost(),
                &[],
                UnixTime::now(),
            )
            .unwrap_err();

        assert!(
            matches!(
                err,
                rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer)
            ),
            "expected UnknownIssuer, got {err:?}"
        );
        assert_eq!(
            authorize_calls.load(Ordering::SeqCst),
            0,
            "authorization must run only after chain validation succeeds"
        );
    }

    /// Same scenario as `server_verifier_rejects_mismatched_trust_anchor_with_uri_only_leaf_and_localhost`,
    /// but with a leaf that includes a DNS SAN: chain failure must still be fatal.
    #[test]
    fn server_verifier_rejects_mismatched_trust_anchor_with_dns_san_leaf() {
        ensure_provider();

        // `cert_with_spiffe` chains to `ca.der`; provider supplies `ca_uri_only.der` only.
        let verifier = SpiffeServerCertVerifier::new(
            static_provider_uri_only_example_org(1),
            |_peer: &SpiffeId| true,
            TrustDomainPolicy::AnyInBundleSet,
        );

        let err = verifier
            .verify_server_cert(
                &cert_with_spiffe(),
                &[],
                &server_name_example_org(),
                &[],
                UnixTime::now(),
            )
            .unwrap_err();

        assert!(!webpki_tls_hostname_mismatch(&err));
        assert!(
            matches!(
                err,
                rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer)
            ),
            "expected UnknownIssuer, got {err:?}"
        );
    }

    #[test]
    fn client_verifier_accepts_authorized_spiffe_id() {
        ensure_provider();

        let verifier = SpiffeClientCertVerifier::new(
            static_provider_example_org(1),
            |id: &SpiffeId| id.to_string() == "spiffe://example.org/service",
            TrustDomainPolicy::AnyInBundleSet,
        );

        let _: rustls::server::danger::ClientCertVerified = verifier
            .verify_client_cert(&cert_with_spiffe(), &[], UnixTime::now())
            .unwrap();
    }

    #[test]
    fn server_verifier_rejects_trust_domain_not_allowed() {
        ensure_provider();

        let policy = TrustDomainPolicy::LocalOnly(
            TrustDomain::new("other.org").expect("valid trust domain"),
        );

        let verifier = SpiffeServerCertVerifier::new(
            static_provider_example_org(1),
            |_peer: &SpiffeId| true,
            policy,
        );

        let err = verifier
            .verify_server_cert(
                &cert_with_spiffe(),
                &[],
                &server_name_example_org(),
                &[],
                UnixTime::now(),
            )
            .unwrap_err();

        let e = assert_other_downcasts_to_error(&err);
        assert!(matches!(e, Error::TrustDomainNotAllowed(td) if td.to_string() == "example.org"));
    }

    #[test]
    fn client_verifier_rejects_trust_domain_not_allowed() {
        ensure_provider();

        let policy = TrustDomainPolicy::LocalOnly(
            TrustDomain::new("other.org").expect("valid trust domain"),
        );

        let verifier = SpiffeClientCertVerifier::new(
            static_provider_example_org(1),
            |_peer: &SpiffeId| true,
            policy,
        );

        let err = verifier
            .verify_client_cert(&cert_with_spiffe(), &[], UnixTime::now())
            .unwrap_err();

        let e = assert_other_downcasts_to_error(&err);
        assert!(matches!(e, Error::TrustDomainNotAllowed(td) if td.to_string() == "example.org"));
    }

    #[test]
    fn server_verifier_rejects_missing_bundle() {
        ensure_provider();

        // Provider contains roots for "other.org" only, but cert is for example.org
        let provider = static_provider_single_td(1, "other.org");

        let verifier = SpiffeServerCertVerifier::new(
            provider,
            |_peer: &SpiffeId| true,
            TrustDomainPolicy::AnyInBundleSet,
        );

        let err = verifier
            .verify_server_cert(
                &cert_with_spiffe(),
                &[],
                &server_name_example_org(),
                &[],
                UnixTime::now(),
            )
            .unwrap_err();

        let e = assert_other_downcasts_to_error(&err);
        assert!(matches!(e, Error::NoBundle(td) if td.to_string() == "example.org"));
    }

    #[test]
    fn client_verifier_rejects_missing_bundle() {
        ensure_provider();

        let provider = static_provider_single_td(1, "other.org");

        let verifier = SpiffeClientCertVerifier::new(
            provider,
            |_peer: &SpiffeId| true,
            TrustDomainPolicy::AnyInBundleSet,
        );

        let err = verifier
            .verify_client_cert(&cert_with_spiffe(), &[], UnixTime::now())
            .unwrap_err();

        let e = assert_other_downcasts_to_error(&err);
        assert!(matches!(e, Error::NoBundle(td) if td.to_string() == "example.org"));
    }

    #[test]
    fn supported_verify_schemes_intersection_is_subset_of_each_td() {
        ensure_provider();

        // Provider with multiple trust domains
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

        let verifier = SpiffeServerCertVerifier::new(
            provider,
            |_peer: &SpiffeId| true,
            TrustDomainPolicy::AnyInBundleSet,
        );

        let schemes_td1 = verifier.supported_schemes_cached(&td1);
        let schemes_td2 = verifier.supported_schemes_cached(&td2);

        let intersection = verifier.supported_verify_schemes();
        assert!(!intersection.is_empty());

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
    fn advertised_verify_schemes_allow_list_uses_only_allowed_trust_domains() {
        ensure_provider();

        let td1 = TrustDomain::new("example.org").expect("valid trust domain");
        let td2 = TrustDomain::new("other.org").expect("valid trust domain");

        let mut roots_by_td = BTreeMap::new();
        roots_by_td.insert(td1.clone(), roots_with_ca());
        roots_by_td.insert(td2, roots_with_ca());

        let snap = MaterialSnapshot {
            generation: 1,
            certified_key: certified_key_from_fixtures(),
            roots_by_td,
        };

        let policy = TrustDomainPolicy::AllowList(BTreeSet::from([td1.clone()]));
        let last_logged_gen = Mutex::new(None);

        let schemes = advertised_verify_schemes(
            "test verifier",
            snap.generation,
            &last_logged_gen,
            &snap,
            &policy,
            |td| {
                if td == &td1 {
                    vec![
                        SignatureScheme::ECDSA_NISTP256_SHA256,
                        SignatureScheme::RSA_PSS_SHA256,
                    ]
                } else {
                    vec![SignatureScheme::ED25519]
                }
            },
        );

        assert_eq!(
            schemes,
            vec![
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::RSA_PSS_SHA256
            ]
        );
    }

    #[test]
    fn server_supported_verify_schemes_policy_excludes_all_returns_empty() {
        ensure_provider();

        let mut roots_by_td = BTreeMap::new();
        let td1 = TrustDomain::new("example.org").expect("valid trust domain");
        let td2 = TrustDomain::new("other.org").expect("valid trust domain");
        roots_by_td.insert(td1, roots_with_ca());
        roots_by_td.insert(td2, roots_with_ca());

        let provider = Arc::new(StaticMaterial(Arc::new(MaterialSnapshot {
            generation: 1,
            certified_key: certified_key_from_fixtures(),
            roots_by_td,
        })));

        let empty: BTreeSet<TrustDomain> = BTreeSet::new();
        let policy = TrustDomainPolicy::AllowList(empty);

        let verifier = SpiffeServerCertVerifier::new(provider, |_peer: &SpiffeId| true, policy);

        let schemes = verifier.supported_verify_schemes();
        assert!(
            schemes.is_empty(),
            "policy excluding all trust domains must not advertise schemes from disallowed bundles"
        );
    }

    #[test]
    fn client_supported_verify_schemes_policy_excludes_all_returns_empty() {
        ensure_provider();

        let mut roots_by_td = BTreeMap::new();
        let td1 = TrustDomain::new("example.org").expect("valid trust domain");
        let td2 = TrustDomain::new("other.org").expect("valid trust domain");
        roots_by_td.insert(td1, roots_with_ca());
        roots_by_td.insert(td2, roots_with_ca());

        let provider = Arc::new(StaticMaterial(Arc::new(MaterialSnapshot {
            generation: 1,
            certified_key: certified_key_from_fixtures(),
            roots_by_td,
        })));

        let empty: BTreeSet<TrustDomain> = BTreeSet::new();
        let policy = TrustDomainPolicy::AllowList(empty);

        let verifier = SpiffeClientCertVerifier::new(provider, |_peer: &SpiffeId| true, policy);

        let schemes = verifier.supported_verify_schemes();
        assert!(
            schemes.is_empty(),
            "policy excluding all trust domains must not advertise schemes from disallowed bundles"
        );
    }

    #[test]
    fn cert_parse_cache_lru_eviction_sanity() {
        // This test exercises CertParseCache deterministically without depending on real cert parsing.
        // Keys are distinct byte strings standing in for full DER encodings.
        fn key(i: u8) -> Vec<u8> {
            vec![i; 40]
        }

        let mut cache = CertParseCache::new();

        // Fill to capacity.
        for i in 0..CertParseCache::CAPACITY {
            cache.insert(
                &key(i),
                CachedLeaf {
                    spiffe_id: SpiffeId::new("spiffe://example.org/service").unwrap(),
                    leaf_check: Ok(()),
                },
            );
        }

        // Touch a middle key so it should not be evicted next.
        let touched = key(10);
        assert!(cache.get(&touched).is_some());

        // Insert one more -> evict LRU (which should be key(0), not key(10)).
        cache.insert(
            &key(u8::MAX),
            CachedLeaf {
                spiffe_id: SpiffeId::new("spiffe://example.org/service").unwrap(),
                leaf_check: Ok(()),
            },
        );

        assert!(
            !cache.entries.contains_key(key(0).as_slice()),
            "expected LRU entry to be evicted"
        );
        assert!(
            cache.entries.contains_key(touched.as_slice()),
            "expected touched entry to remain"
        );
    }

    #[test]
    fn lookup_or_parse_leaf_caches_invalid_leaf_result() {
        // A signing cert must be reported invalid on both the cache-miss (first) and
        // cache-hit (second) paths, so caching never turns a rejection into acceptance.
        let cache: Mutex<CertParseCache> = Mutex::new(CertParseCache::new());
        let cert = cert_ca_with_spiffe_signing();

        let first = lookup_or_parse_leaf(&cert, Some(&cache)).unwrap();
        assert!(first.leaf_check.is_err(), "first (miss) must reject leaf");

        let second = lookup_or_parse_leaf(&cert, Some(&cache)).unwrap();
        assert!(
            second.leaf_check.is_err(),
            "second (hit) must still reject leaf"
        );
        assert_eq!(first.spiffe_id, second.spiffe_id);
    }

    #[test]
    fn extract_spiffe_id_with_cache_hits_best_effort() {
        // This test validates the cache wiring (hit path) without requiring timing/alloc assertions.
        let cache: Mutex<CertParseCache> = Mutex::new(CertParseCache::new());
        let cert = cert_with_spiffe();

        // First call populates (best effort).
        let id1 = extract_spiffe_id_with_cache(&cert, Some(&cache)).unwrap();
        // Second call should hit and return the same result.
        let id2 = extract_spiffe_id_with_cache(&cert, Some(&cache)).unwrap();

        assert_eq!(id1, id2);
    }

    #[test]
    fn verifier_cache_does_not_panic_across_generations() {
        // This is a pragmatic regression test: the cache key includes generation; ensure
        // supported_verify_schemes() remains stable when material generation changes.

        #[derive(Clone)]
        struct MutableMaterial(Arc<Mutex<Arc<MaterialSnapshot>>>);
        impl MaterialProvider for MutableMaterial {
            fn current_material(&self) -> Arc<MaterialSnapshot> {
                lock_mutex(&self.0).unwrap().clone()
            }
        }

        ensure_provider();

        let mut roots_by_td = BTreeMap::new();
        let td = TrustDomain::new("example.org").unwrap();
        roots_by_td.insert(td, roots_with_ca());

        let snap1 = Arc::new(MaterialSnapshot {
            generation: 1,
            certified_key: certified_key_from_fixtures(),
            roots_by_td: roots_by_td.clone(),
        });

        let snap2 = Arc::new(MaterialSnapshot {
            generation: 2,
            certified_key: certified_key_from_fixtures(),
            roots_by_td,
        });

        let provider = Arc::new(MutableMaterial(Arc::new(Mutex::new(snap1))));

        let verifier = {
            let provider = Arc::clone(&provider);
            SpiffeServerCertVerifier::new(
                provider,
                |_peer: &SpiffeId| true,
                TrustDomainPolicy::AnyInBundleSet,
            )
        };

        let s1 = verifier.supported_verify_schemes();
        assert!(!s1.is_empty());

        // Swap snapshot generation.
        *lock_mutex(&provider.0).unwrap() = snap2;

        let s2 = verifier.supported_verify_schemes();
        assert!(!s2.is_empty());
    }

    /// [`MaterialProvider`] whose snapshot can be swapped after construction,
    /// used to simulate a build failure (empty root store) followed by a
    /// recovery (valid root store) for the *same* cache key.
    #[derive(Clone)]
    struct MutableMaterial(Arc<Mutex<Arc<MaterialSnapshot>>>);

    impl MaterialProvider for MutableMaterial {
        fn current_material(&self) -> Arc<MaterialSnapshot> {
            lock_mutex(&self.0).unwrap().clone()
        }
    }

    fn snapshot_with_roots(
        generation: u64,
        td: &TrustDomain,
        roots: Arc<RootCertStore>,
    ) -> Arc<MaterialSnapshot> {
        let mut roots_by_td = BTreeMap::new();
        roots_by_td.insert(td.clone(), roots);
        Arc::new(MaterialSnapshot {
            generation,
            certified_key: certified_key_from_fixtures(),
            roots_by_td,
        })
    }

    #[test]
    fn server_build_cell_recovers_after_build_failure() {
        // Regression test for the single-flight build cell: a failed build
        // (here, an empty root store rejected by rustls at `build()` time)
        // must leave the cell able to build again for the same cache key
        // (same generation + trust domain), not wedged in `Building`.
        ensure_provider();

        let td = TrustDomain::new("example.org").unwrap();
        let provider = Arc::new(MutableMaterial(Arc::new(Mutex::new(snapshot_with_roots(
            1,
            &td,
            Arc::new(RootCertStore::empty()),
        )))));

        let verifier = SpiffeServerCertVerifier::new(
            Arc::<MutableMaterial>::clone(&provider),
            |_peer: &SpiffeId| true,
            TrustDomainPolicy::AnyInBundleSet,
        );

        match verifier.get_or_build_inner(&td) {
            Ok(_) => panic!("expected build to fail with an empty root store"),
            Err(Error::VerifierBuilder(_)) => {}
            Err(other) => panic!("expected Error::VerifierBuilder, got {other:?}"),
        }

        // Same generation and trust domain (same cache key), but now with a
        // usable root store: the cell must have reverted to `Empty` and allow
        // a fresh build attempt to succeed.
        *lock_mutex(&provider.0).unwrap() = snapshot_with_roots(1, &td, roots_with_ca());

        let value = verifier
            .get_or_build_inner(&td)
            .expect("build must succeed once the root store is valid");
        assert!(!value.schemes.is_empty());
    }

    #[test]
    fn server_build_cell_concurrent_waiters_recover_after_build_failure() {
        // Several threads race to build for the same key while the build
        // fails; all must observe the failure (none may hang on the condvar),
        // and a subsequent build with valid roots must still succeed. Bounded
        // by `thread::Builder` join with no external timeout: if the fix
        // regresses, this test hangs rather than silently passing.
        ensure_provider();

        let td = TrustDomain::new("example.org").unwrap();
        let provider = Arc::new(MutableMaterial(Arc::new(Mutex::new(snapshot_with_roots(
            1,
            &td,
            Arc::new(RootCertStore::empty()),
        )))));

        let verifier = Arc::new(SpiffeServerCertVerifier::new(
            Arc::<MutableMaterial>::clone(&provider),
            |_peer: &SpiffeId| true,
            TrustDomainPolicy::AnyInBundleSet,
        ));

        let handles: Vec<_> = std::iter::repeat_with(|| {
            let verifier = Arc::clone(&verifier);
            let td = td.clone();
            std::thread::spawn(move || {
                matches!(
                    verifier.get_or_build_inner(&td),
                    Err(Error::VerifierBuilder(_))
                )
            })
        })
        .take(8)
        .collect();

        for h in handles {
            assert!(
                h.join().expect("waiter thread must not panic"),
                "every waiter must observe Error::VerifierBuilder, not hang or panic"
            );
        }

        *lock_mutex(&provider.0).unwrap() = snapshot_with_roots(1, &td, roots_with_ca());

        let value = verifier
            .get_or_build_inner(&td)
            .expect("build must succeed once the root store is valid");
        assert!(!value.schemes.is_empty());
    }
}
