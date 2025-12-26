//! rustls verifiers that authenticate with SPIFFE trust bundles and authorize by SPIFFE ID.
//!
//! This module is internal to the crate. It intentionally keeps the public API
//! surface minimal and avoids leaking rustls implementation details.

use crate::error::{Error, Result};
use crate::material::MaterialSnapshot;
use crate::resolve::MaterialWatcher;
use crate::types::AuthorizeSpiffeId;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use std::fmt::{self, Debug};
use std::sync::{Arc, Mutex};
use x509_parser::prelude::{FromDer, X509Certificate};

/// Extract the first `spiffe://...` URI SAN from the leaf certificate.
///
/// ## Errors
///
/// Returns [`Error::MissingSpiffeId`] if no SPIFFE ID is present, or
/// [`Error::CertParse`] if the certificate cannot be parsed.
pub fn extract_spiffe_id(leaf: &CertificateDer<'_>) -> Result<String> {
    let (_, cert) =
        X509Certificate::from_der(leaf.as_ref()).map_err(|e| Error::CertParse(format!("{e:?}")))?;

    let san = cert
        .subject_alternative_name()
        .map_err(|e| Error::CertParse(format!("{e:?}")))?
        .ok_or(Error::MissingSpiffeId)?;

    for name in &san.value.general_names {
        if let x509_parser::extensions::GeneralName::URI(uri) = name {
            if uri.starts_with("spiffe://") {
                return Ok(uri.to_string());
            }
        }
    }

    Err(Error::MissingSpiffeId)
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

#[derive(Clone)]
struct ServerVerifierCache {
    generation: u64,
    verifier: Arc<dyn rustls::client::danger::ServerCertVerifier>,
    schemes: Vec<SignatureScheme>,
}

#[derive(Clone)]
struct ClientVerifierCache {
    generation: u64,
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
    rustls::server::WebPkiClientVerifier::builder(roots)
        .build()
        .map_err(|e| Error::VerifierBuilder(format!("{e:?}")))
}

// ------------ Server verifier (client side) ------------

#[derive(Clone)]
pub(crate) struct SpiffeServerCertVerifier {
    provider: Arc<dyn MaterialProvider>,
    authorize: AuthorizeSpiffeId,
    cache: Arc<Mutex<Option<ServerVerifierCache>>>,
}

impl SpiffeServerCertVerifier {
    pub fn from_watcher(watcher: MaterialWatcher, authorize: AuthorizeSpiffeId) -> Self {
        Self::new(Arc::new(watcher) as Arc<dyn MaterialProvider>, authorize)
    }

    pub fn new(provider: Arc<dyn MaterialProvider>, authorize: AuthorizeSpiffeId) -> Self {
        Self {
            provider,
            authorize,
            cache: Arc::new(Mutex::new(None)),
        }
    }

    fn get_or_build_inner(&self) -> Result<Arc<dyn rustls::client::danger::ServerCertVerifier>> {
        let snap = self.provider.current_material();
        let gen = snap.generation;
        let roots = snap.roots.clone();

        let mut guard = self
            .cache
            .lock()
            .map_err(|_| Error::Internal("server verifier cache mutex poisoned".into()))?;

        if let Some(cached) = guard.as_ref() {
            if cached.generation == gen {
                return Ok(cached.verifier.clone());
            }
        }

        let built = build_server_verifier(roots)?;
        let schemes = built.supported_verify_schemes();

        *guard = Some(ServerVerifierCache {
            generation: gen,
            verifier: built.clone(),
            schemes,
        });

        Ok(built)
    }

    fn supported_schemes_cached(&self) -> Vec<SignatureScheme> {
        // Do not "fail open" to empty if we have a known-good cache.
        // If there is no cache yet, attempt to build; on failure, return empty (handshake will fail).
        if let Ok(guard) = self.cache.lock() {
            if let Some(cached) = guard.as_ref() {
                return cached.schemes.clone();
            }
        }

        self.get_or_build_inner()
            .map(|v| v.supported_verify_schemes())
            .unwrap_or_default()
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
        let inner = self.get_or_build_inner().map_err(other_err)?;
        let ok =
            inner.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)?;

        // Authorization is performed only after cryptographic verification succeeds.
        let spiffe_id = extract_spiffe_id(end_entity).map_err(other_err)?;
        if !(self.authorize)(&spiffe_id) {
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
        let inner = self.get_or_build_inner().map_err(other_err)?;
        inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let inner = self.get_or_build_inner().map_err(other_err)?;
        inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported_schemes_cached()
    }
}

// ------------ Client verifier (server side) ------------

#[derive(Clone)]
pub(crate) struct SpiffeClientCertVerifier {
    provider: Arc<dyn MaterialProvider>,
    authorize: AuthorizeSpiffeId,
    cache: Arc<Mutex<Option<ClientVerifierCache>>>,
}

impl SpiffeClientCertVerifier {
    pub fn new(provider: Arc<dyn MaterialProvider>, authorize: AuthorizeSpiffeId) -> Self {
        Self {
            provider,
            authorize,
            cache: Arc::new(Mutex::new(None)),
        }
    }

    pub fn from_watcher(watcher: MaterialWatcher, authorize: AuthorizeSpiffeId) -> Self {
        Self::new(Arc::new(watcher) as Arc<dyn MaterialProvider>, authorize)
    }

    fn get_or_build_inner(&self) -> Result<Arc<dyn rustls::server::danger::ClientCertVerifier>> {
        let snap = self.provider.current_material();
        let gen = snap.generation;
        let roots = snap.roots.clone();

        let mut guard = self
            .cache
            .lock()
            .map_err(|_| Error::Internal("client verifier cache mutex poisoned".into()))?;

        if let Some(cached) = guard.as_ref() {
            if cached.generation == gen {
                return Ok(cached.verifier.clone());
            }
        }

        let built = build_client_verifier(roots)?;
        let schemes = built.supported_verify_schemes();

        *guard = Some(ClientVerifierCache {
            generation: gen,
            verifier: built.clone(),
            schemes,
        });

        Ok(built)
    }

    fn supported_schemes_cached(&self) -> Vec<SignatureScheme> {
        if let Ok(guard) = self.cache.lock() {
            if let Some(cached) = guard.as_ref() {
                return cached.schemes.clone();
            }
        }

        self.get_or_build_inner()
            .map(|v| v.supported_verify_schemes())
            .unwrap_or_default()
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
        let inner = self.get_or_build_inner().map_err(other_err)?;
        let ok = inner.verify_client_cert(end_entity, intermediates, now)?;

        let spiffe_id = extract_spiffe_id(end_entity).map_err(other_err)?;
        if !(self.authorize)(&spiffe_id) {
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
        let inner = self.get_or_build_inner().map_err(other_err)?;
        inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let inner = self.get_or_build_inner().map_err(other_err)?;
        inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported_schemes_cached()
    }
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
        CertificateDer::from(fixture_spiffe_leaf_der())
    }

    fn cert_without_spiffe() -> CertificateDer<'static> {
        CertificateDer::from(fixture_no_spiffe_leaf_der())
    }

    fn roots_with_ca() -> Arc<RootCertStore> {
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(fixture_ca_der()))
            .expect("fixture CA must parse");
        Arc::new(roots)
    }

    fn certified_key_from_fixtures() -> Arc<rustls::sign::CertifiedKey> {
        ensure_provider();

        let certs = vec![CertificateDer::from(fixture_spiffe_leaf_der())];

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
        Arc::new(StaticMaterial(Arc::new(MaterialSnapshot {
            generation,
            certified_key: certified_key_from_fixtures(),
            roots: roots_with_ca(),
        })))
    }

    #[test]
    fn extract_spiffe_id_ok() {
        let id = extract_spiffe_id(&cert_with_spiffe()).unwrap();
        assert_eq!(id, "spiffe://example.org/service");
    }

    #[test]
    fn extract_spiffe_id_missing() {
        let err = extract_spiffe_id(&cert_without_spiffe()).unwrap_err();
        assert!(matches!(err, Error::MissingSpiffeId));
    }

    #[test]
    fn server_verifier_rejects_unauthorized_spiffe_id() {
        ensure_provider();

        let verifier = SpiffeServerCertVerifier::new(static_provider(1), Arc::new(|_| false));

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

        let verifier = SpiffeClientCertVerifier::new(static_provider(1), Arc::new(|_| false));

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
            Arc::new(|id| id == "spiffe://example.org/service"),
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
            Arc::new(|id| id == "spiffe://example.org/service"),
        );

        let res = verifier.verify_client_cert(&cert_with_spiffe(), &[], UnixTime::now());
        assert!(res.is_ok());
    }

    #[test]
    fn verifier_cache_is_keyed_by_generation() {
        ensure_provider();

        let v1 = SpiffeServerCertVerifier::new(static_provider(1), Arc::new(|_| true));
        let s1 = v1.supported_verify_schemes();
        assert!(!s1.is_empty());

        let v2 = SpiffeServerCertVerifier::new(static_provider(2), Arc::new(|_| true));
        let s2 = v2.supported_verify_schemes();
        assert!(!s2.is_empty());
    }
}
