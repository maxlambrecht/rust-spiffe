//! Peer identity extraction from TLS connections.

use crate::error::Error;
use rustls::client::ClientConnection;
use rustls::server::ServerConnection;
use spiffe::SpiffeId;

/// Peer identity extracted from a TLS connection.
///
/// After a successful TLS handshake, the peer's SPIFFE ID (if present) is extracted
/// from their certificate's URI SAN.
///
/// # SPIFFE X.509-SVID Expectations
///
/// According to the SPIFFE specification, an X.509-SVID must contain **exactly one** SPIFFE ID
/// in the URI SAN, and peers are expected to present certificates when mTLS is required.
/// When using `spiffe-rustls` verifiers correctly, these requirements are enforced during
/// the TLS handshake, and cases where `spiffe_id` is `None` should normally be unreachable.
///
/// # Extraction Semantics
///
/// This crate performs post-handshake identity extraction from connections that have already passed TLS verification.
/// The API behavior is:
///
/// - **Exactly one SPIFFE ID**: Extracted and stored in `spiffe_id`
/// - **Missing SPIFFE ID**: `spiffe_id` is `None` (no error; `accept()`/`connect()` succeed)
///   - **SPIFFE perspective**: Invalid X.509-SVID; unexpected in SPIFFE-compliant configurations
/// - **Multiple SPIFFE IDs**: `spiffe_id` is `None` (no error; `accept()`/`connect()` succeed)
///   - **SPIFFE perspective**: Invalid X.509-SVID; unexpected in SPIFFE-compliant configurations
/// - **No peer certificates**: `spiffe_id` is `None` (no error; `accept()`/`connect()` succeed)
///   - **SPIFFE perspective**: Invalid for mTLS; unexpected in SPIFFE-compliant configurations
/// - **Certificate parse failure**: Returns `Error::CertParse` (`accept()`/`connect()` fail)
///
/// **Note**: A `None` value for `spiffe_id` is unexpected in SPIFFE-compliant configurations
/// and may indicate that the TLS configuration is not enforcing SPIFFE semantics, or that
/// the peer is not presenting a valid SPIFFE X.509-SVID.
#[derive(Debug, Clone)]
pub struct PeerIdentity {
    /// The SPIFFE ID extracted from the peer's certificate, if present.
    pub spiffe_id: Option<SpiffeId>,
}

impl PeerIdentity {
    /// Creates a new `PeerIdentity` with the given SPIFFE ID.
    pub fn new(spiffe_id: Option<SpiffeId>) -> Self {
        Self { spiffe_id }
    }

    /// Returns the peer's SPIFFE ID, if present.
    pub fn spiffe_id(&self) -> Option<&SpiffeId> {
        self.spiffe_id.as_ref()
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

/// Extracts the SPIFFE ID from peer certificates.
///
/// This function extracts the SPIFFE ID from the leaf (first) certificate in the
/// peer's certificate chain. The certificates are obtained from a verified rustls
/// connection after a successful TLS handshake.
///
/// # SPIFFE X.509-SVID Expectations
///
/// According to the SPIFFE specification, an X.509-SVID must contain **exactly one** SPIFFE ID
/// in the URI SAN, and peers are expected to present certificates when mTLS is required.
/// Cases where `spiffe_id` is `None` are unexpected in SPIFFE-compliant configurations and
/// may indicate misconfiguration or a non-SPIFFE peer.
///
/// # Behavior
///
/// - **Exactly one SPIFFE ID**: Extracted and returned in `PeerIdentity`
/// - **Zero SPIFFE IDs**: Returns `PeerIdentity { spiffe_id: None }` (no error)
///   - **SPIFFE perspective**: Invalid X.509-SVID; unexpected in SPIFFE-compliant configurations
/// - **Multiple SPIFFE IDs**: Returns `PeerIdentity { spiffe_id: None }` (no error)
///   - **SPIFFE perspective**: Invalid X.509-SVID; unexpected in SPIFFE-compliant configurations
/// - **No peer certificates**: Returns `PeerIdentity { spiffe_id: None }` (no error)
///   - **SPIFFE perspective**: Invalid for mTLS; unexpected in SPIFFE-compliant configurations
/// - **Certificate parse failure**: Returns `Error::CertParse`
///
/// # Errors
///
/// Returns an error if the certificate cannot be parsed (e.g., malformed DER).
/// Missing or multiple SPIFFE IDs do not cause an error; they result in `spiffe_id` being `None`.
fn extract_peer_identity_impl(
    peer_certs: Option<&[rustls::pki_types::CertificateDer<'_>]>,
) -> Result<PeerIdentity, Error> {
    // Handle case where no peer certificates are present
    let peer_certs = match peer_certs {
        Some(certs) if !certs.is_empty() => certs,
        _ => {
            // No peer certificates - return identity with None
            // This is invalid per SPIFFE X.509-SVID spec for mTLS, but we return None
            // rather than error to allow graceful handling. In SPIFFE-compliant
            // configurations using spiffe-rustls verifiers, this case should be
            // unreachable as verifiers require peer certificates for mTLS.
            return Ok(PeerIdentity::new(None));
        }
    };

    // Extract from the leaf certificate (first in the chain)

    let leaf_cert = &peer_certs[0];

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
        let empty: &[CertificateDer] = &[];
        let identity = extract_peer_identity_impl(Some(empty)).unwrap();
        assert!(identity.spiffe_id().is_none());
    }

    #[test]
    fn test_peer_identity_creation() {
        let identity = PeerIdentity::new(None);
        assert!(identity.spiffe_id().is_none());

        let spiffe_id = spiffe::SpiffeId::try_from("spiffe://example.org/test").unwrap();
        let identity = PeerIdentity::new(Some(spiffe_id.clone()));
        assert_eq!(identity.spiffe_id(), Some(&spiffe_id));
    }
}
