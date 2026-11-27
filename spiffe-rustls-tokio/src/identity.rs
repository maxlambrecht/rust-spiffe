//! Peer identity extraction from TLS connections.

use crate::error::Error;
use rustls::client::ClientConnection;
use rustls::server::ServerConnection;
use spiffe::SpiffeId;

/// SPIFFE ID extracted from the leaf certificate after a successful TLS handshake.
///
/// Extraction uses the certificate accepted by the configured TLS verifier.
/// With the SPIFFE mTLS verifiers, the handshake enforces the peer identity
/// requirements. With other TLS configurations, extraction has these outcomes.
///
/// - `Some` when the leaf has a single URI SAN that parses as a SPIFFE ID.
/// - `None` when there is no peer certificate, or a present SAN contains no
///   SPIFFE URI and passes parsing.
/// - [`Error::CertParse`] when the leaf has no SAN extension, has multiple URI
///   SAN entries, or otherwise fails identity parsing.
///
/// Extraction alone performs no additional certificate trust or authorization
/// checks. Use [`Self::spiffe_id`] or [`Self::require_spiffe_id`] to access the result.
#[derive(Debug, Clone)]
pub struct PeerIdentity {
    /// The SPIFFE ID extracted from the peer's certificate, if present.
    spiffe_id: Option<SpiffeId>,
}

impl PeerIdentity {
    /// Creates a new `PeerIdentity` with the given SPIFFE ID.
    pub const fn new(spiffe_id: Option<SpiffeId>) -> Self {
        Self { spiffe_id }
    }

    /// Returns the peer's SPIFFE ID, if present.
    pub const fn spiffe_id(&self) -> Option<&SpiffeId> {
        self.spiffe_id.as_ref()
    }

    /// Returns the peer's SPIFFE ID, or [`Error::MissingSpiffeId`] if absent.
    ///
    /// Use this for a fail-closed alternative to [`spiffe_id`](Self::spiffe_id)
    /// when the caller requires a SPIFFE ID. Authentication depends on the
    /// configured TLS verifier.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MissingSpiffeId`] when no SPIFFE ID was extracted from the
    /// peer certificate.
    pub fn require_spiffe_id(&self) -> Result<&SpiffeId, Error> {
        self.spiffe_id.as_ref().ok_or(Error::MissingSpiffeId)
    }
}

/// Extracts the SPIFFE ID from a server connection's peer certificates.
pub(crate) fn extract_peer_identity_from_server(
    connection: &ServerConnection,
) -> Result<PeerIdentity, Error> {
    let peer_certs = connection.peer_certificates();
    extract_peer_identity_impl(peer_certs)
}

/// Extracts the SPIFFE ID from a client connection's peer certificates.
pub(crate) fn extract_peer_identity_from_client(
    connection: &ClientConnection,
) -> Result<PeerIdentity, Error> {
    let peer_certs = connection.peer_certificates();
    extract_peer_identity_impl(peer_certs)
}

/// Applies the post-handshake extraction policy documented on [`PeerIdentity`].
fn extract_peer_identity_impl(
    peer_certs: Option<&[rustls::pki_types::CertificateDer<'_>]>,
) -> Result<PeerIdentity, Error> {
    let Some([leaf_cert, ..]) = peer_certs else {
        // No peer certificates - return identity with None
        // This is invalid per SPIFFE X.509-SVID spec for mTLS, but we return None
        // rather than error to allow graceful handling. In SPIFFE-compliant
        // configurations using spiffe-rustls verifiers, this case should be
        // unreachable as verifiers require peer certificates for mTLS.
        return Ok(PeerIdentity::new(None));
    };

    // Extract SPIFFE ID from the leaf certificate
    match spiffe::cert::spiffe_id_from_der(leaf_cert.as_ref()) {
        Ok(spiffe_id) => Ok(PeerIdentity::new(Some(spiffe_id))),
        Err(e) => {
            // Map certificate errors appropriately
            use spiffe::cert::error::CertificateError as CE;
            match e {
                CE::MissingSpiffeId | CE::MultipleSpiffeIds => {
                    // These are invalid per SPIFFE X.509-SVID spec, but we return None
                    // rather than error to allow graceful handling. In SPIFFE-compliant
                    // configurations using spiffe-rustls verifiers, these cases should be
                    // unreachable as verifiers enforce exactly one SPIFFE ID.
                    Ok(PeerIdentity::new(None))
                }
                _ => Err(Error::CertParse(e.to_string())),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{extract_peer_identity_impl, PeerIdentity};
    use rustls::pki_types::CertificateDer;

    #[test]
    fn test_peer_identity_none_when_no_certs() {
        let identity = extract_peer_identity_impl(None).unwrap();
        assert!(identity.spiffe_id().is_none());
    }

    #[test]
    fn test_peer_identity_none_when_empty_certs() {
        let empty: &[CertificateDer<'_>] = &[];
        let identity = extract_peer_identity_impl(Some(empty)).unwrap();
        assert!(identity.spiffe_id().is_none());
    }

    #[test]
    fn test_peer_identity_uri_san_outcomes() {
        let [spiffe_uri, non_spiffe_uri, multiple_uri, no_san] = [
            CertificateDer::from(include_bytes!("../tests/fixtures/spiffe-uri.der").as_slice()),
            CertificateDer::from(include_bytes!("../tests/fixtures/non-spiffe-uri.der").as_slice()),
            CertificateDer::from(include_bytes!("../tests/fixtures/multiple-uri.der").as_slice()),
            CertificateDer::from(include_bytes!("../tests/fixtures/no-san.der").as_slice()),
        ];
        let expected = spiffe::SpiffeId::new("spiffe://example.org/workload").unwrap();
        assert_eq!(
            extract_peer_identity_impl(Some(std::slice::from_ref(&spiffe_uri)))
                .unwrap()
                .spiffe_id(),
            Some(&expected)
        );
        assert!(
            extract_peer_identity_impl(Some(std::slice::from_ref(&non_spiffe_uri)))
                .unwrap()
                .spiffe_id()
                .is_none()
        );
        for cert in [&multiple_uri, &no_san] {
            assert!(matches!(
                extract_peer_identity_impl(Some(std::slice::from_ref(cert))),
                Err(crate::Error::CertParse(_))
            ));
        }
    }

    #[test]
    fn test_peer_identity_creation() {
        let identity = PeerIdentity::new(None);
        assert!(identity.spiffe_id().is_none());

        let spiffe_id = spiffe::SpiffeId::try_from("spiffe://example.org/test").unwrap();
        let identity = PeerIdentity::new(Some(spiffe_id.clone()));
        assert_eq!(identity.spiffe_id(), Some(&spiffe_id));
    }

    #[test]
    fn test_require_spiffe_id_ok_when_present() {
        let spiffe_id = spiffe::SpiffeId::try_from("spiffe://example.org/test").unwrap();
        let identity = PeerIdentity::new(Some(spiffe_id.clone()));
        assert_eq!(identity.require_spiffe_id().unwrap(), &spiffe_id);
    }

    #[test]
    fn test_require_spiffe_id_err_when_absent() {
        let identity = PeerIdentity::new(None);
        assert!(matches!(
            identity.require_spiffe_id(),
            Err(crate::error::Error::MissingSpiffeId)
        ));
    }
}
