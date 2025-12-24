use crate::error::{Error, Result};
use crate::resolve::MaterialWatcher;
use crate::types::AuthorizeSpiffeId;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, RootCertStore, SignatureScheme};
use std::fmt::Debug;
use std::sync::Arc;
use x509_parser::prelude::{FromDer, X509Certificate};

pub fn extract_spiffe_id(leaf: &CertificateDer<'_>) -> Result<String> {
    let (_, cert) =
        X509Certificate::from_der(leaf.as_ref()).map_err(|e| Error::CertParse(format!("{e:?}")))?;

    let san = cert
        .subject_alternative_name()
        .map_err(|e| Error::CertParse(format!("{e:?}")))?
        .ok_or(Error::MissingSpiffeId)?;

    for name in san.value.general_names.iter() {
        if let x509_parser::extensions::GeneralName::URI(uri) = name
            && uri.starts_with("spiffe://")
        {
            return Ok(uri.to_string());
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

/// Provides the current set of trusted root certificates for TLS verification.
///
/// This abstraction exists to support dynamic trust bundle rotation (e.g. SPIFFE
/// bundle updates) without rebuilding `rustls::ClientConfig` / `ServerConfig`
/// or forcing transport reconnections.
pub(crate) trait RootsProvider: Send + Sync {
    fn current_roots(&self) -> Arc<RootCertStore>;
}

impl RootsProvider for MaterialWatcher {
    fn current_roots(&self) -> Arc<RootCertStore> {
        self.current().roots.clone()
    }
}

#[derive(Clone)]
pub(crate) struct SpiffeServerCertVerifier {
    roots: Arc<dyn RootsProvider>,
    authorize: AuthorizeSpiffeId,
}

impl SpiffeServerCertVerifier {
    pub fn new(roots: Arc<dyn RootsProvider>, authorize: AuthorizeSpiffeId) -> Result<Self> {
        Ok(Self { roots, authorize })
    }

    fn inner(&self) -> Result<Arc<dyn rustls::client::danger::ServerCertVerifier>> {
        let roots = self.roots.current_roots();
        let inner = rustls::client::WebPkiServerVerifier::builder(roots)
            .build()
            .map_err(|e| Error::VerifierBuilder(format!("{e:?}")))?;
        Ok(inner)
    }
}

impl Debug for SpiffeServerCertVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
        let inner = self.inner().map_err(other_err)?;
        let ok =
            inner.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)?;

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
        let inner = self.inner().map_err(other_err)?;
        inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let inner = self.inner().map_err(other_err)?;
        inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        // If verifier build fails here, returning empty is safer than panicking.
        self.inner()
            .map(|v| v.supported_verify_schemes())
            .unwrap_or_default()
    }
}

#[derive(Clone)]
pub(crate) struct SpiffeClientCertVerifier {
    roots: Arc<dyn RootsProvider>,
    authorize: AuthorizeSpiffeId,
}

impl SpiffeClientCertVerifier {
    pub fn new(roots: Arc<dyn RootsProvider>, authorize: AuthorizeSpiffeId) -> Result<Self> {
        Ok(Self { roots, authorize })
    }

    fn inner(&self) -> Result<Arc<dyn rustls::server::danger::ClientCertVerifier>> {
        let roots = self.roots.current_roots();
        let inner = rustls::server::WebPkiClientVerifier::builder(roots)
            .build()
            .map_err(|e| Error::VerifierBuilder(format!("{e:?}")))?;
        Ok(inner)
    }
}

impl Debug for SpiffeClientCertVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpiffeClientCertVerifier").finish()
    }
}

impl rustls::server::danger::ClientCertVerifier for SpiffeClientCertVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> std::result::Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        let inner = self.inner().map_err(other_err)?;
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
        let inner = self.inner().map_err(other_err)?;
        inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let inner = self.inner().map_err(other_err)?;
        inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner()
            .map(|v| v.supported_verify_schemes())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::RootCertStore;
    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::server::danger::ClientCertVerifier;
    use std::sync::Arc;

    fn ensure_provider() {
        static ONCE: std::sync::OnceLock<()> = std::sync::OnceLock::new();
        ONCE.get_or_init(crate::crypto::ensure_crypto_provider_installed);
    }

    fn cert_with_spiffe() -> CertificateDer<'static> {
        let bytes = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/spiffe_leaf.der"
        ));
        CertificateDer::from(bytes.as_slice())
    }

    fn cert_without_spiffe() -> CertificateDer<'static> {
        let bytes = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/no_spiffe_leaf.der"
        ));
        CertificateDer::from(bytes.as_slice())
    }

    #[derive(Clone)]
    struct StaticRoots(Arc<RootCertStore>);

    impl RootsProvider for StaticRoots {
        fn current_roots(&self) -> Arc<RootCertStore> {
            self.0.clone()
        }
    }

    fn roots_with_ca() -> Arc<RootCertStore> {
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/ca.der"
            )) as &[u8]))
            .unwrap();
        Arc::new(roots)
    }

    #[test]
    fn extract_spiffe_id_ok() {
        let cert = cert_with_spiffe();
        let id = extract_spiffe_id(&cert).unwrap();
        assert_eq!(id, "spiffe://example.org/service");
    }

    #[test]
    fn extract_spiffe_id_missing() {
        let cert = cert_without_spiffe();
        let err = extract_spiffe_id(&cert).unwrap_err();
        assert!(matches!(err, Error::MissingSpiffeId));
    }

    #[test]
    fn server_verifier_rejects_unauthorized_spiffe_id() {
        ensure_provider();

        let verifier = SpiffeServerCertVerifier::new(
            Arc::new(StaticRoots(roots_with_ca())),
            Arc::new(|_| false),
        )
        .unwrap();

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

        let verifier = SpiffeClientCertVerifier::new(
            Arc::new(StaticRoots(roots_with_ca())),
            Arc::new(|_| false),
        )
        .unwrap();

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
            Arc::new(StaticRoots(roots_with_ca())),
            Arc::new(|id| id == "spiffe://example.org/service"),
        )
        .unwrap();

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
            Arc::new(StaticRoots(roots_with_ca())),
            Arc::new(|id| id == "spiffe://example.org/service"),
        )
        .unwrap();

        let res = verifier.verify_client_cert(&cert_with_spiffe(), &[], UnixTime::now());
        assert!(res.is_ok());
    }
}
