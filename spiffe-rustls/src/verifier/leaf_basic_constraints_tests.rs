//! Peer leaf `BasicConstraints`: signed certificates, real TLS verification, and cache-hit regressions.

use super::*;

#[derive(Clone, Copy, Debug)]
enum Rejection {
    Missing,
    Ca,
    Malformed,
    Domain,
    Unauthorized,
}

fn assert_rejection(err: &rustls::Error, expected: Rejection) {
    if matches!(expected, Rejection::Malformed) {
        assert_eq!(
            err,
            &rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        );
        return;
    }
    let rustls::Error::Other(other) = err else {
        panic!("expected SPIFFE peer rejection ({expected:?}), got {err:?}");
    };
    let error = other.0.downcast_ref::<Error>().unwrap();
    match (expected, error) {
        (Rejection::Missing, Error::InvalidLeaf(reason)) => {
            assert_eq!(reason, "basic constraints extension is missing");
        }
        (Rejection::Ca, Error::InvalidLeaf(reason)) => {
            assert_eq!(
                reason,
                "basic constraints CA is set to true (signing certificate)"
            );
        }
        (Rejection::Domain, Error::TrustDomainNotAllowed(domain)) => {
            assert_eq!(domain.to_string(), "other.org");
        }
        (Rejection::Unauthorized, Error::UnauthorizedSpiffeId(id)) => {
            assert_eq!(id.to_string(), "spiffe://example.org/unauthorized");
        }
        _ => panic!("expected {expected:?}, got {error:?}"),
    }
}

fn presented_key(chain: Vec<CertificateDer<'static>>) -> Arc<rustls::sign::CertifiedKey> {
    crate::crypto::ensure_crypto_provider_installed();
    let crypto = rustls::crypto::CryptoProvider::get_default().unwrap();
    let der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        include_bytes!("../../tests/fixtures/issuer_key_usage/leaf.pkcs8").as_slice(),
    ));
    // Loading the matching fixture key directly allows malformed BC to reach the
    // peer verifier; CertifiedKey::from_der may reject it locally via webpki.
    Arc::new(rustls::sign::CertifiedKey::new(
        chain,
        crypto.key_provider.load_private_key(der).unwrap(),
    ))
}

fn authorizer(calls: &Arc<AtomicUsize>) -> impl Authorizer + use<> {
    let calls = Arc::clone(calls);
    move |id: &SpiffeId| {
        calls.fetch_add(1, Ordering::SeqCst);
        id.to_string() == "spiffe://example.org/workload"
    }
}

fn handshake_matrix(version: &'static rustls::SupportedProtocolVersion) {
    for role in ROLES {
        for (leaf, rejection) in [
            (fixture!("leaf-basic-constraints"), None),
            (
                fixture!("leaf-no-basic-constraints"),
                Some(Rejection::Missing),
            ),
            (fixture!("leaf-ca"), Some(Rejection::Ca)),
            (
                fixture!("leaf-malformed-basic-constraints"),
                Some(Rejection::Malformed),
            ),
            (fixture!("leaf-wrong-domain"), Some(Rejection::Domain)),
            (fixture!("leaf-unauthorized"), Some(Rejection::Unauthorized)),
            // Positive authentication still works after the negative controls.
            (fixture!("leaf-basic-constraints"), None),
        ] {
            let peer = vec![leaf, fixture!("issuer-good")];
            let good = vec![fixture!("leaf-direct")];
            let (client_chain, server_chain) = match role {
                Role::Server => (good, peer),
                Role::Client => (peer, good),
            };
            let trusted = material(&[fixture!("root")], "example.org");
            let calls = Arc::new(AtomicUsize::new(0));
            // Count only the verifier under test, independently of the other peer.
            let other_calls = Arc::new(AtomicUsize::new(0));
            let server_verifier = Arc::new(SpiffeServerCertVerifier::new(
                Arc::clone(&trusted),
                authorizer(match role {
                    Role::Server => &calls,
                    Role::Client => &other_calls,
                }),
                TrustDomainPolicy::LocalOnly("example.org".try_into().unwrap()),
            ));
            let client_verifier = Arc::new(SpiffeClientCertVerifier::new(
                trusted,
                authorizer(match role {
                    Role::Client => &calls,
                    Role::Server => &other_calls,
                }),
                TrustDomainPolicy::LocalOnly("example.org".try_into().unwrap()),
            ));
            assert!(client_verifier.offer_client_auth());
            assert!(client_verifier.client_auth_mandatory());
            let crypto = Arc::clone(rustls::crypto::CryptoProvider::get_default().unwrap());
            let mut client = rustls::ClientConfig::builder_with_details(
                Arc::clone(&crypto),
                Arc::new(FixedTime),
            )
            .with_protocol_versions(&[version])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(server_verifier)
            .with_client_cert_resolver(Arc::new(ClientKey(presented_key(client_chain))));
            client.resumption = rustls::client::Resumption::disabled();
            let mut server =
                rustls::ServerConfig::builder_with_details(crypto, Arc::new(FixedTime))
                    .with_protocol_versions(&[version])
                    .unwrap()
                    .with_client_cert_verifier(client_verifier)
                    .with_cert_resolver(Arc::new(ServerKey(presented_key(server_chain))));
            server.send_tls13_tickets = 0;
            server.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
            let (client, server) = (Arc::new(client), Arc::new(server));
            // Same configs/verifiers and full DER on the second handshake: cache hit.
            for attempt in 1..=2 {
                let result = complete_handshake(Arc::clone(&client), Arc::clone(&server), version);
                if let Some(expected) = rejection {
                    let (failed_role, err) = result.expect_err("nonconforming peer authenticated");
                    assert!(matches!(
                        (role, failed_role),
                        (Role::Server, Role::Server) | (Role::Client, Role::Client)
                    ));
                    assert_rejection(&err, expected);
                } else {
                    result.unwrap(); // Includes negotiated version and bidirectional app bytes.
                }
                let authorized =
                    rejection.is_none() || matches!(rejection, Some(Rejection::Unauthorized));
                assert_eq!(
                    calls.load(Ordering::SeqCst),
                    if authorized { attempt } else { 0 }
                );
            }
        }
    }
}

#[test]
fn tls13_peer_basic_constraints() {
    handshake_matrix(&rustls::version::TLS13);
}

#[test]
fn tls12_peer_basic_constraints() {
    // tls12 is a dev-dependency feature: fail instead of silently skipping a lane.
    handshake_matrix(&rustls::version::TLS12);
}

#[test]
fn basic_constraints_cache_miss_and_hit() {
    for (leaf, expected) in [
        (fixture!("leaf-basic-constraints"), Ok(())),
        (
            fixture!("leaf-no-basic-constraints"),
            Err("basic constraints extension is missing".to_owned()),
        ),
        (
            fixture!("leaf-ca"),
            Err("basic constraints CA is set to true (signing certificate)".to_owned()),
        ),
        // Malformed BC is rejected by rustls path validation.
        (fixture!("leaf-malformed-basic-constraints"), Ok(())),
    ] {
        let cache = Mutex::new(CertParseCache::new());
        assert!(lock_mutex(&cache).unwrap().get(leaf.as_ref()).is_none());
        for _ in 0..2 {
            let parsed = lookup_or_parse_leaf(&leaf, Some(&cache)).unwrap();
            assert_eq!(parsed.leaf_check, expected);
            assert_eq!(
                lock_mutex(&cache)
                    .unwrap()
                    .get(leaf.as_ref())
                    .unwrap()
                    .leaf_check,
                expected
            );
        }
    }
}
