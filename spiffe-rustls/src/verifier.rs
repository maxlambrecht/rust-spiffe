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
use std::hash::{Hash, Hasher as _};
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

const CERT_PREFIX_LEN: usize = 32;

/// Non-cryptographic certificate fingerprint used only as a cache key.
///
///  (hash of full DER + length + DER prefix) minimizes collisions while remaining dependency-free.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
struct CertFingerprint {
    hash: u64,
    len: usize,
    prefix: [u8; CERT_PREFIX_LEN],
}

fn cert_fingerprint(cert: &CertificateDer<'_>) -> CertFingerprint {
    let bytes = cert.as_ref();

    let mut hasher = DefaultHasher::new();
    bytes.hash(&mut hasher);
    let hash = hasher.finish();

    let mut prefix = [0u8; CERT_PREFIX_LEN];
    prefix.iter_mut().zip(bytes).for_each(|(d, &s)| *d = s);

    CertFingerprint {
        hash,
        len: bytes.len(),
        prefix,
    }
}

/// Cached result of extracting SPIFFE ID from a certificate.
#[derive(Clone, Debug)]
struct CachedSpiffeId {
    spiffe_id: SpiffeId,
}

/// Bounded certificate parse cache with simple LRU eviction.
///
/// Capacity is small (64), so we keep the implementation dependency-free.
/// Touch operations are O(capacity) which is acceptable at this size.
struct CertParseCache {
    entries: HashMap<CertFingerprint, CachedSpiffeId>,
    order: VecDeque<CertFingerprint>,
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

    fn get(&mut self, key: CertFingerprint) -> Option<CachedSpiffeId> {
        let value = self.entries.get(&key).cloned()?;

        // (O(n) remove; acceptable for small capacity)
        if let Some(pos) = self.order.iter().position(|k| *k == key) {
            self.order.remove(pos);
        }
        self.order.push_back(key);

        Some(value)
    }

    fn insert(&mut self, key: CertFingerprint, value: CachedSpiffeId) {
        if let std::collections::hash_map::Entry::Occupied(mut e) = self.entries.entry(key) {
            e.insert(value);
            self.touch(key);
            return;
        }

        if self.entries.len() >= self.capacity {
            self.evict_lru();
        }

        self.entries.insert(key, value);
        self.order.push_back(key);
    }

    fn touch(&mut self, key: CertFingerprint) {
        if let Some(pos) = self.order.iter().position(|k| *k == key) {
            self.order.remove(pos);
        }
        self.order.push_back(key);
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

fn extract_spiffe_id_with_cache(
    leaf: &CertificateDer<'_>,
    cache: Option<&Mutex<CertParseCache>>,
) -> Result<SpiffeId> {
    let key = cert_fingerprint(leaf);

    if let Some(cache) = cache {
        if let Ok(mut guard) = lock_mutex(cache) {
            if let Some(cached) = guard.get(key) {
                return Ok(cached.spiffe_id);
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

    if let Some(cache) = cache {
        if let Ok(mut guard) = lock_mutex(cache) {
            guard.insert(
                key,
                CachedSpiffeId {
                    spiffe_id: spiffe_id.clone(),
                },
            );
        }
    }

    Ok(spiffe_id)
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
struct ServerVerifierCacheValue {
    verifier: Arc<dyn rustls::client::danger::ServerCertVerifier>,
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
    pub(crate) fn new(
        provider: Arc<dyn MaterialProvider>,
        authorizer: impl Authorizer,
        policy: TrustDomainPolicy,
    ) -> Self {
        Self {
            provider,
            authorizer: Arc::new(authorizer),
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

            match guard.as_ref() {
                Some(entry) if entry.key == cache_key => Arc::clone(&entry.cell),
                _ => {
                    let cell = Arc::new(ServerBuildCell::new());
                    *guard = Some(ServerVerifierCache {
                        key: cache_key,
                        cell: Arc::clone(&cell),
                    });
                    cell
                }
            }
        };

        loop {
            let mut guard = lock_mutex(&cell.state)
                .map_err(|()| Error::Internal("server verifier cache mutex poisoned".into()))?;

            match &*guard {
                ServerBuildState::Ready(v) => return Ok(Arc::clone(&v.verifier)),

                ServerBuildState::Empty => {
                    // Become the single builder (no race window).
                    *guard = ServerBuildState::Building;
                    drop(guard);

                    // Build without holding any locks.
                    let verifier = match build_server_verifier(roots) {
                        Ok(v) => v,
                        Err(e) => {
                            // Reset + notify waiters; do not cache failure.
                            let mut g = lock_mutex(&cell.state).map_err(|()| {
                                Error::Internal("server verifier cache mutex poisoned".into())
                            })?;
                            *g = ServerBuildState::Empty;
                            drop(g);
                            cell.cv.notify_all();
                            return Err(e);
                        }
                    };

                    let schemes = verifier.supported_verify_schemes();
                    let value = ServerVerifierCacheValue { verifier, schemes };

                    // Publish success and wake waiters.
                    let mut g = lock_mutex(&cell.state).map_err(|()| {
                        Error::Internal("server verifier cache mutex poisoned".into())
                    })?;
                    let verifier = Arc::clone(&value.verifier);
                    *g = ServerBuildState::Ready(value);
                    drop(g);
                    cell.cv.notify_all();
                    return Ok(verifier);
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
                .as_ref()
                .filter(|e| e.key.1 == *trust_domain)
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
            Ok(v) => v.supported_verify_schemes(),
            Err(e) => {
                debug!(
                "failed to build server verifier for trust domain {trust_domain}: {e}; returning empty schemes (handshake will fail)");
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
    pub(crate) fn new(
        provider: Arc<dyn MaterialProvider>,
        authorizer: impl Authorizer,
        policy: TrustDomainPolicy,
    ) -> Self {
        Self {
            provider,
            authorizer: Arc::new(authorizer),
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

            match guard.as_ref() {
                Some(entry) if entry.key == cache_key => Arc::clone(&entry.cell),
                _ => {
                    let cell = Arc::new(ClientBuildCell::new());
                    *guard = Some(ClientVerifierCache {
                        key: cache_key,
                        cell: Arc::clone(&cell),
                    });
                    cell
                }
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

                    let verifier = match build_client_verifier(roots) {
                        Ok(v) => v,
                        Err(e) => {
                            // Reset + notify waiters; do not cache failure.
                            let mut g = lock_mutex(&cell.state).map_err(|()| {
                                Error::Internal("client verifier cache mutex poisoned".into())
                            })?;
                            *g = ClientBuildState::Empty;
                            drop(g);
                            cell.cv.notify_all();
                            return Err(e);
                        }
                    };

                    let schemes = verifier.supported_verify_schemes();
                    let value = ClientVerifierCacheValue { verifier, schemes };

                    let mut g = lock_mutex(&cell.state).map_err(|()| {
                        Error::Internal("client verifier cache mutex poisoned".into())
                    })?;
                    let verifier = Arc::clone(&value.verifier);
                    *g = ClientBuildState::Ready(value);
                    drop(g);
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
                .as_ref()
                .filter(|e| e.key.1 == *trust_domain)
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
        // Step 1: Extract SPIFFE ID from certificate
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
    r#gen: u64,
    last_logged_gen: &Mutex<Option<u64>>,
    snap: &MaterialSnapshot,
    policy: &TrustDomainPolicy,
    mut per_td_schemes: impl FnMut(&spiffe::TrustDomain) -> Vec<SignatureScheme>,
    mut build_union_schemes: impl FnMut(
        &spiffe::TrustDomain,
        Arc<rustls::RootCertStore>,
    ) -> Result<Vec<SignatureScheme>>,
) -> Vec<SignatureScheme> {
    // Collect schemes for trust domains allowed by policy.
    let mut scheme_sets: Vec<Vec<SignatureScheme>> = Vec::new();

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
    if let Some(first) = scheme_sets.first() {
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
            (snapshot trust domains: {snapshot_tds}); falling back to scheme union to surface policy error");
    }

    // Build union of schemes from all trust domains
    // Note: Using Vec with contains() for deduplication since SignatureScheme doesn't implement Hash.
    // The number of schemes is typically small (< 10), so O(n²) is acceptable.
    let mut union: Vec<SignatureScheme> = Vec::new();

    for (td, roots) in &snap.roots_by_td {
        let schemes = match build_union_schemes(td, Arc::clone(roots)) {
            Ok(s) => s,
            Err(e) => {
                debug!(
                    "{label}: failed to build verifier for trust domain {td} while computing scheme union: {e}");
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
    fn supported_verify_schemes_policy_excludes_all_falls_back_to_union() {
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

        // Exclude all trust domains via an empty allow-list. This should trigger the
        // fallback-union behavior in advertised_verify_schemes().
        let empty: BTreeSet<TrustDomain> = BTreeSet::new();
        let policy = TrustDomainPolicy::AllowList(empty);

        let verifier = SpiffeServerCertVerifier::new(provider, |_peer: &SpiffeId| true, policy);

        let schemes = verifier.supported_verify_schemes();
        assert!(
            !schemes.is_empty(),
            "fallback should advertise a union to avoid NoSignatureSchemes"
        );
    }

    #[test]
    // #[expect(clippy::cast_possible_truncation)]
    fn cert_parse_cache_lru_eviction_sanity() {
        // This test exercises CertParseCache deterministically without depending on real cert parsing.
        fn key(i: u8) -> CertFingerprint {
            CertFingerprint {
                hash: i.into(),
                len: i.into(),
                prefix: [i; CERT_PREFIX_LEN],
            }
        }

        let mut cache = CertParseCache::new();

        // Fill to capacity.
        for i in 0..CertParseCache::CAPACITY {
            cache.insert(
                key(i),
                CachedSpiffeId {
                    spiffe_id: SpiffeId::new("spiffe://example.org/service").unwrap(),
                },
            );
        }

        // Touch a middle key so it should not be evicted next.
        let touched = key(10);
        assert!(cache.get(touched).is_some());

        // Insert one more -> evict LRU (which should be key(0), not key(10)).
        cache.insert(
            key(u8::MAX),
            CachedSpiffeId {
                spiffe_id: SpiffeId::new("spiffe://example.org/service").unwrap(),
            },
        );

        assert!(
            !cache.entries.contains_key(&key(0)),
            "expected LRU entry to be evicted"
        );
        assert!(
            cache.entries.contains_key(&touched),
            "expected touched entry to remain"
        );
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
}
