use crate::error::{Error, Result};
use log::debug;
use rustls::RootCertStore;
use rustls::pki_types::CertificateDer;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub(crate) struct MaterialSnapshot {
    pub certified_key: Arc<rustls::sign::CertifiedKey>,
    pub roots: Arc<RootCertStore>,
}

pub(crate) fn roots_from_bundle_der(bundle_authorities: &[Vec<u8>]) -> Result<Arc<RootCertStore>> {
    let mut store = RootCertStore::empty();

    let ders: Vec<CertificateDer<'static>> = bundle_authorities
        .iter()
        .cloned()
        .map(CertificateDer::from)
        .collect();

    let added = store.add_parsable_certificates(ders);

    debug!("loaded root cert(s): {:?}", added);

    if store.is_empty() {
        return Err(Error::Internal(
            "no root certificates were accepted into RootCertStore".into(),
        ));
    }

    Ok(Arc::new(store))
}

pub(crate) fn certified_key_from_der(
    cert_chain_der: &[Vec<u8>],
    private_key_pkcs8_der: &[u8],
) -> Result<Arc<rustls::sign::CertifiedKey>> {
    let certs: Vec<rustls::pki_types::CertificateDer<'static>> = cert_chain_der
        .iter()
        .map(|c| rustls::pki_types::CertificateDer::from(c.clone()))
        .collect();

    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(private_key_pkcs8_der.to_vec()),
    );

    let provider = rustls::crypto::CryptoProvider::get_default()
        .ok_or_else(|| Error::CertifiedKey("rustls crypto provider is not installed".into()))?;

    let signing_key = provider
        .key_provider
        .load_private_key(key_der)
        .map_err(|e| Error::CertifiedKey(format!("{e:?}")))?;

    Ok(Arc::new(rustls::sign::CertifiedKey::new(
        certs,
        signing_key,
    )))
}
