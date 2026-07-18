use crate::error::{Error, Result};
use crate::prelude::debug;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::RootCertStore;
use spiffe::TrustDomain;
use std::collections::BTreeMap;
use std::sync::Arc;

/// Snapshot of rustls material with federation support.
///
/// Contains the current SVID and a map of trust domain -> root cert store
/// for federation-aware verification.
#[derive(Clone, Debug)]
pub(crate) struct MaterialSnapshot {
    pub generation: u64,
    pub certified_key: Arc<rustls::sign::CertifiedKey>,
    /// Map of trust domain to root certificate store.
    ///
    /// This enables federation: we can verify certificates from any
    /// trust domain for which we have a bundle.
    pub roots_by_td: BTreeMap<TrustDomain, Arc<RootCertStore>>,
}

/// Build a `RootCertStore` from DER-encoded certificate authorities.
///
/// # Errors
///
/// Returns [`Error::EmptyRootStore`] if no certificates are accepted into the store.
/// This can occur if the certificates are malformed, expired, or otherwise invalid.
pub(crate) fn roots_from_certs(certs: &[CertificateDer<'static>]) -> Result<Arc<RootCertStore>> {
    let mut store = RootCertStore::empty();

    let added = store.add_parsable_certificates(certs.iter().cloned());

    debug!("loaded root cert(s): {added:?}");

    if store.is_empty() {
        return Err(Error::EmptyRootStore);
    }

    Ok(Arc::new(store))
}

/// Build a rustls `CertifiedKey` from a cert chain and a PKCS#8 private key.
///
/// This verifies that the private key matches the leaf certificate's SPKI
/// (via `CertifiedKey::from_der`'s `keys_match` check), so mismatched material
/// fails here at build time instead of later, opaquely, at handshake/signing time.
///
/// ## Errors
///
/// Returns [`Error::CertifiedKey`] if the crypto provider is not installed,
/// the key can't be loaded, or the key does not match the leaf certificate.
pub(crate) fn certified_key_from_chain_and_key(
    cert_chain: Vec<CertificateDer<'static>>,
    private_key_pkcs8_der: &[u8],
) -> Result<Arc<rustls::sign::CertifiedKey>> {
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(private_key_pkcs8_der.to_vec()));

    let provider = rustls::crypto::CryptoProvider::get_default()
        .ok_or_else(|| Error::CertifiedKey("rustls crypto provider is not installed".into()))?;

    let certified_key = rustls::sign::CertifiedKey::from_der(cert_chain, key_der, provider)
        .map_err(|e| Error::CertifiedKey(format!("{e:?}")))?;

    Ok(Arc::new(certified_key))
}

/// Helper: build owned DER certificates from an iterator of DER bytes.
///
/// This prevents higher layers from passing around `Vec<Vec<u8>>`.
fn owned_certs_from_der_bytes<'a, I>(ders: I) -> Vec<CertificateDer<'static>>
where
    I: IntoIterator<Item = &'a [u8]>,
{
    ders.into_iter()
        .map(|b| CertificateDer::from(b.to_vec()))
        .collect()
}

/// Helper: build an owned cert chain from an iterator of DER bytes.
///
/// Alias of [`certs_from_der_bytes`] kept for readability at call sites
/// that build a leaf-to-root chain rather than a root store.
pub(crate) fn cert_chain_from_der_bytes<'a, I>(ders: I) -> Vec<CertificateDer<'static>>
where
    I: IntoIterator<Item = &'a [u8]>,
{
    owned_certs_from_der_bytes(ders)
}

/// Helper: build owned root certs from an iterator of DER bytes.
pub(crate) fn certs_from_der_bytes<'a, I>(ders: I) -> Vec<CertificateDer<'static>>
where
    I: IntoIterator<Item = &'a [u8]>,
{
    owned_certs_from_der_bytes(ders)
}
