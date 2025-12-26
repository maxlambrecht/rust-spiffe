use crate::error::{Error, Result};
use log::debug;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::RootCertStore;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub(crate) struct MaterialSnapshot {
    pub generation: u64,
    pub certified_key: Arc<rustls::sign::CertifiedKey>,
    pub roots: Arc<RootCertStore>,
}

/// Build a `RootCertStore` from DER-encoded certificate authorities.
///
/// ## Errors
///
/// Returns [`Error::Internal`] if no certificates are accepted into the store.
pub(crate) fn roots_from_certs(certs: &[CertificateDer<'static>]) -> Result<Arc<RootCertStore>> {
    let mut store = RootCertStore::empty();

    let added = store.add_parsable_certificates(certs.iter().cloned());

    debug!("loaded root cert(s): {added:?}");

    if store.is_empty() {
        return Err(Error::Internal(
            "no root certificates were accepted into RootCertStore".into(),
        ));
    }

    Ok(Arc::new(store))
}

/// Build a rustls `CertifiedKey` from a cert chain and a PKCS#8 private key.
///
/// ## Errors
///
/// Returns [`Error::CertifiedKey`] if the crypto provider is not installed
/// or the key can't be loaded.
pub(crate) fn certified_key_from_chain_and_key(
    cert_chain: Vec<CertificateDer<'static>>,
    private_key_pkcs8_der: &[u8],
) -> Result<Arc<rustls::sign::CertifiedKey>> {
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(private_key_pkcs8_der.to_vec()));

    let provider = rustls::crypto::CryptoProvider::get_default()
        .ok_or_else(|| Error::CertifiedKey("rustls crypto provider is not installed".into()))?;

    let signing_key = provider
        .key_provider
        .load_private_key(key_der)
        .map_err(|e| Error::CertifiedKey(format!("{e:?}")))?;

    Ok(Arc::new(rustls::sign::CertifiedKey::new(
        cert_chain,
        signing_key,
    )))
}

/// Helper: build an owned cert chain from an iterator of DER bytes.
///
/// This prevents higher layers from passing around `Vec<Vec<u8>>`.
pub(crate) fn cert_chain_from_der_bytes<'a, I>(ders: I) -> Vec<CertificateDer<'static>>
where
    I: IntoIterator<Item = &'a [u8]>,
{
    ders.into_iter()
        .map(|b| CertificateDer::from(b.to_vec()))
        .collect()
}

/// Helper: build owned root certs from an iterator of DER bytes.
pub(crate) fn certs_from_der_bytes<'a, I>(ders: I) -> Vec<CertificateDer<'static>>
where
    I: IntoIterator<Item = &'a [u8]>,
{
    ders.into_iter()
        .map(|b| CertificateDer::from(b.to_vec()))
        .collect()
}
