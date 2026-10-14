use super::*;

macro_rules! issuer {
    ($name:literal) => {
        include_bytes!(concat!("../fixtures/issuer_key_usage/", $name, ".der")).as_slice()
    };
}

#[derive(Debug, PartialEq)]
enum Rejector {
    Client,
    Server,
}

#[expect(
    clippy::unwrap_in_result,
    clippy::panic_in_result_fn,
    reason = "test setup and in-memory I/O are infallible; return the rejecting verifier"
)]
fn path_handshake(
    client: Arc<rustls::ClientConfig>,
    server: Arc<rustls::ServerConfig>,
) -> Result<(), (Rejector, rustls::Error)> {
    let mut client = rustls::ClientConnection::new(
        client, ServerName::try_from("example.org").unwrap(),
    ).unwrap();
    let mut server = rustls::ServerConnection::new(server).unwrap();
    for _ in 0..32 {
        let mut bytes = Vec::new();
        client.write_tls(&mut bytes).unwrap();
        if !bytes.is_empty() {
            server.read_tls(&mut Cursor::new(bytes)).unwrap();
            server.process_new_packets().map_err(|error| (Rejector::Server, error))?;
        }
        let mut bytes = Vec::new();
        server.write_tls(&mut bytes).unwrap();
        if !bytes.is_empty() {
            client.read_tls(&mut Cursor::new(bytes)).unwrap();
            client.process_new_packets().map_err(|error| (Rejector::Client, error))?;
        }
        if !client.is_handshaking() && !server.is_handshaking() {
            return Ok(());
        }
    }
    panic!("path regression handshake stalled");
}

fn check_path(configs: &Configs, issuers: &[&[u8]], accepted: bool) {
    let chain: Vec<_> = std::iter::once(issuer!("leaf"))
        .chain(issuers.iter().copied()).map(cert).collect();
    let private_key = include_bytes!("../fixtures/issuer_key_usage/leaf.pkcs8");
    for version in [&rustls::version::TLS13, &rustls::version::TLS12] {
        let peer_client = Arc::new(
            rustls::ClientConfig::builder_with_protocol_versions(&[version])
                .with_root_certificates(roots())
                .with_client_auth_cert(chain.clone(), key(private_key)).unwrap(),
        );
        let peer_server = Arc::new(
            rustls::ServerConfig::builder_with_protocol_versions(&[version])
                .with_client_cert_verifier(
                    rustls::server::WebPkiClientVerifier::builder(Arc::new(roots()))
                        .build().unwrap(),
                )
                .with_single_cert(chain.clone(), key(private_key)).unwrap(),
        );
        for (rejector, result) in [
            (Rejector::Client, path_handshake(Arc::clone(&configs.client), peer_server)),
            (Rejector::Server, path_handshake(peer_client, Arc::clone(&configs.server))),
        ] {
            if accepted {
                result.unwrap();
            } else {
                let (actual, error) = result.unwrap_err();
                assert_eq!(actual, rejector);
                assert!(matches!(error, rustls::Error::InvalidCertificate(
                    rustls::CertificateError::UnknownIssuer
                )), "{version:?}: {error:?}");
            }
        }
    }
}

#[tokio::test]
async fn issuer_constraints_survive_failed_conversion_trust_rotation_and_reauthorization() {
    let (source, tx, _metrics, server) =
        source(response(A, KA, issuer!("root"), "", false), false).await;
    let mut configs = Configs::new(&source, spiffe_rustls::TerminalSourcePolicy::RetainFinal);
    let mut updates = source.updated();
    // Warm both caches before altering authoritative trust, using the same peer leaf throughout.
    check_path(&configs, &[issuer!("issuer-good")], true);
    check_path(&configs, &[issuer!("issuer-digital-signature")], false);
    check_path(&configs, &[
        issuer!("issuer-cross-restricted"), issuer!("upper-restricted"),
        issuer!("issuer-cross-good"), issuer!("upper-good"),
    ], true);
    check_path(&configs, &[issuer!("issuer-cross-restricted"), issuer!("upper-restricted")], false);

    let _old = tx.send_replace(Ok(response(A, KB, issuer!("root-b"), "", false)));
    assert_eq!(updates.changed().await.unwrap(), 1);
    configs.applied(1).await;
    assert!(!configs.client_status.current().available);
    assert!(matches!(configs.client_status.current().error.as_deref(),
        Some(spiffe_rustls::Error::MaterialUnavailable(cause))
        if matches!(cause.as_ref(), spiffe_rustls::Error::CertifiedKey(_))));

    let replacement = response(A, KA, issuer!("root-b"), "", false);
    let _old = tx.send_replace(Ok(replacement.clone()));
    assert_eq!(updates.changed().await.unwrap(), 2);
    configs.applied(2).await;
    check_path(&configs, &[issuer!("issuer-good")], false);
    check_path(&configs, &[issuer!("issuer-digital-signature")], false);
    check_path(&configs, &[issuer!("issuer-untrusted")], true);
    check_path(&configs, &[issuer!("issuer-digital-signature"), issuer!("issuer-untrusted")], true);

    let _old = tx.send_replace(Err(tonic::Status::permission_denied("withdrawn")));
    assert_eq!(updates.changed().await.unwrap(), 3);
    assert!(matches!(configs.server_status.current().error.as_deref(),
        Some(spiffe_rustls::Error::Source(spiffe::x509_source::X509SourceError::Withdrawn(_)))));
    let _old = tx.send_replace(Ok(replacement));
    assert_eq!(updates.changed().await.unwrap(), 4);
    configs.applied(4).await;
    check_path(&configs, &[issuer!("issuer-good")], false);
    check_path(&configs, &[issuer!("issuer-digital-signature")], false);
    check_path(&configs, &[issuer!("issuer-untrusted")], true);
    source.shutdown().await;
    configs.terminated().await;
    check_path(&configs, &[issuer!("issuer-good")], false);
    check_path(&configs, &[issuer!("issuer-untrusted")], true);
    server.abort();
}
