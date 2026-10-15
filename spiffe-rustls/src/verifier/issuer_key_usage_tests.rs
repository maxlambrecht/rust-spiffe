//! Issuer `KeyUsage`: fixed-time peer path and protocol regressions, without a Workload API.

use super::*;
use rustls::client::danger::ServerCertVerifier as _;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::danger::ClientCertVerifier as _;
use std::collections::BTreeMap;
use std::io::{Read as _, Write as _};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

macro_rules! fixture {
    ($name:literal) => {
        CertificateDer::from(
            include_bytes!(concat!(
                "../../tests/fixtures/issuer_key_usage/",
                $name,
                ".der"
            ))
            .as_slice(),
        )
    };
}

#[path = "leaf_basic_constraints_tests.rs"]
mod leaf_basic_constraints_tests;

#[derive(Clone, Copy, Debug)]
enum Role {
    Server,
    Client,
}

const ROLES: [Role; 2] = [Role::Server, Role::Client];

fn now() -> UnixTime {
    UnixTime::since_unix_epoch(Duration::from_secs(1_893_456_000))
}

#[test]
fn selected_crypto_provider() {
    crate::crypto::ensure_crypto_provider_installed();
    #[cfg(feature = "ring")]
    let expected = rustls::crypto::ring::default_provider();
    #[cfg(feature = "aws-lc-rs")]
    let expected = rustls::crypto::aws_lc_rs::default_provider();
    let installed = rustls::crypto::CryptoProvider::get_default().unwrap();
    assert_eq!(installed.cipher_suites, expected.cipher_suites);
    let actual = installed.signature_verification_algorithms.all;
    let expected = expected.signature_verification_algorithms.all;
    assert_eq!(actual.len(), expected.len());
    for (actual, expected) in actual.iter().zip(expected) {
        assert!(std::ptr::eq(*actual, *expected));
    }
}

#[test]
fn complete_extension_oid_der() {
    for valid in [
        &[0x55, 0x1d, 0x0f][..],
        &[0x00],
        &[0x7f],
        &[0x81, 0x00],
        &[0xff, 0x7f],
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01],
    ] {
        assert!(extension_oid_is_der(valid));
    }
    for invalid in [
        &[][..],
        &[0x80, 0x00],
        &[0x55, 0x80, 0x1d, 0x0f],
        &[0x55, 0x1d, 0x80, 0x0f],
        &[0x55, 0x1d, 0x80, 0x80, 0x0f],
        &[0x81],
        &[0x55, 0x81],
    ] {
        assert!(!extension_oid_is_der(invalid));
    }
}

#[test]
fn complete_key_usage_der() {
    // Exhaust the defined nonempty named-bit combinations, including two-octet KU.
    for bits in 1u16..512 {
        let first = u8::try_from(bits & 0xff).unwrap().reverse_bits();
        let der = if bits & 0x100 == 0 {
            vec![
                0x03,
                0x02,
                u8::try_from(first.trailing_zeros()).unwrap(),
                first,
            ]
        } else {
            vec![0x03, 0x03, 0x07, first, 0x80]
        };
        assert_eq!(key_usage_allows_certificate_signing(&der), bits & 0x20 != 0);
        for end in 0..der.len() {
            assert!(!key_usage_allows_certificate_signing(
                der.as_slice().get(..end).unwrap()
            ));
        }
        let mut trailing = der;
        trailing.extend_from_slice(&[0x05, 0x00]);
        assert!(!key_usage_allows_certificate_signing(&trailing));
    }
    for unused in 0u8..=255 {
        assert_eq!(
            key_usage_allows_certificate_signing(&[0x03, 0x02, unused, 0x04]),
            unused == 2
        );
        assert_eq!(
            key_usage_allows_certificate_signing(&[0x03, 0x03, unused, 0x04, 0x80]),
            unused == 7
        );
        assert!(!key_usage_allows_certificate_signing(&[
            0x03, 0x03, unused, 0x04, 0x00
        ]));
    }
}

#[test]
fn candidate_parsing_fails_closed_and_borrows_der() {
    let good = fixture!("issuer-good");
    let mut trailing = good.as_ref().to_vec();
    trailing.extend_from_slice(&[0x05, 0x00]);
    assert!(!issuer_allows_certificate_signing(&CertificateDer::from(
        trailing
    )));
    for end in 0..good.as_ref().len() {
        assert!(!issuer_allows_certificate_signing(&CertificateDer::from(
            good.as_ref().get(..end).unwrap()
        )));
    }
    assert!(eligible_intermediates(&[]).is_none());
    assert!(eligible_intermediates(std::slice::from_ref(&good)).is_none());
    let chain = [
        good.clone(),
        fixture!("issuer-wrong-tag"),
        fixture!("issuer-missing"),
    ];
    let eligible = eligible_intermediates(&chain).unwrap();
    assert_eq!(eligible, [good, fixture!("issuer-missing")]);
    assert_eq!(
        eligible.first().unwrap().as_ref().as_ptr(),
        chain[0].as_ref().as_ptr()
    );
    assert_eq!(
        eligible.as_slice().get(1).unwrap().as_ref().as_ptr(),
        chain[2].as_ref().as_ptr()
    );
}

fn key(chain: Vec<CertificateDer<'static>>) -> Arc<rustls::sign::CertifiedKey> {
    crate::crypto::ensure_crypto_provider_installed();
    let provider = rustls::crypto::CryptoProvider::get_default().unwrap();
    let der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        include_bytes!("../../tests/fixtures/issuer_key_usage/leaf.pkcs8").as_slice(),
    ));
    Arc::new(rustls::sign::CertifiedKey::from_der(chain, der, provider).unwrap())
}

struct StaticMaterial(Arc<MaterialSnapshot>);

impl MaterialProvider for StaticMaterial {
    fn current_material(&self) -> Result<Arc<MaterialSnapshot>> {
        Ok(Arc::clone(&self.0))
    }
}

fn material(anchors: &[CertificateDer<'static>], domain: &str) -> Arc<dyn MaterialProvider> {
    let mut roots = rustls::RootCertStore::empty();
    for anchor in anchors {
        roots.add(anchor.clone()).unwrap();
    }
    Arc::new(StaticMaterial(Arc::new(MaterialSnapshot {
        generation: 0,
        certified_key: key(vec![fixture!("leaf-direct")]),
        roots_by_td: BTreeMap::from([(domain.try_into().unwrap(), Arc::new(roots))]),
    })))
}

#[expect(
    clippy::unwrap_in_result,
    clippy::panic_in_result_fn,
    reason = "Result carries verifier rejections; invalid fixtures and assertions fail the test"
)]
fn verify(
    role: Role,
    leaf: &CertificateDer<'_>,
    chain: &[CertificateDer<'_>],
    provider: Arc<dyn MaterialProvider>,
    policy: TrustDomainPolicy,
    authorize: bool,
    calls: &Arc<AtomicUsize>,
) -> std::result::Result<(), rustls::Error> {
    let calls = Arc::clone(calls);
    let authorizer = move |id: &SpiffeId| {
        calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(id.to_string(), "spiffe://example.org/workload");
        authorize
    };
    match role {
        Role::Server => SpiffeServerCertVerifier::new(provider, authorizer, policy)
            .verify_server_cert(
                leaf,
                chain,
                &ServerName::try_from("localhost").unwrap(),
                &[],
                now(),
            )
            .map(|_| ()),
        Role::Client => SpiffeClientCertVerifier::new(provider, authorizer, policy)
            .verify_client_cert(leaf, chain, now())
            .map(|_| ()),
    }
}

fn assert_path(leaf: &CertificateDer<'static>, chain: &[CertificateDer<'static>], accepted: bool) {
    assert_path_to(leaf, chain, &[fixture!("root")], accepted);
}

fn assert_path_to(
    leaf: &CertificateDer<'static>,
    chain: &[CertificateDer<'static>],
    anchors: &[CertificateDer<'static>],
    accepted: bool,
) {
    for role in ROLES {
        let calls = Arc::new(AtomicUsize::new(0));
        let result = verify(
            role,
            leaf,
            chain,
            material(anchors, "example.org"),
            TrustDomainPolicy::AnyInBundleSet,
            true,
            &calls,
        );
        if accepted {
            result.unwrap_or_else(|err| panic!("{role:?} rejected permitted path: {err:?}"));
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        } else {
            let err = result.expect_err("issuer must not be accepted or authorized");
            assert!(
                matches!(err, rustls::Error::InvalidCertificate(_)),
                "{role:?}: {err:?}"
            );
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        }
    }
}

macro_rules! rejected_issuers {
    ($($test:ident => $fixture:literal),+ $(,)?) => {$ (
        #[test]
        fn $test() {
            assert_path(&fixture!("leaf"), &[fixture!($fixture)], false);
        }
    )+};
}

rejected_issuers! {
    digital_signature_only => "issuer-digital-signature",
    crl_sign_only => "issuer-crl-sign",
    noncritical_forbidden_usage => "issuer-noncritical",
    malformed_wrong_tag => "issuer-wrong-tag",
    duplicate_key_usage => "issuer-duplicate",
    trailing_inner_der => "issuer-trailing",
    truncated_bit_string => "issuer-truncated",
    empty_bit_string => "issuer-empty",
    invalid_unused_bits => "issuer-invalid-unused",
    invalid_padding => "issuer-invalid-padding",
    nonminimal_named_bits => "issuer-nonminimal-bits",
    nonminimal_der_length => "issuer-nonminimal-length",
    nonminimal_extension_oid => "issuer-nonminimal-oid",
    undefined_usage_bit => "issuer-undefined-bit",
    constructed_bit_string => "issuer-constructed",
    indefinite_length => "issuer-indefinite",
    non_ca_issuer => "issuer-not-ca",
    issuer_eku_still_enforced => "issuer-wrong-eku",
}

#[test]
fn permitted_and_missing_usage() {
    for issuer in [
        fixture!("issuer-good"),
        fixture!("issuer-key-cert-sign"),
        fixture!("issuer-missing"),
        fixture!("issuer-good-noncritical"),
        fixture!("issuer-decipher-only"),
    ] {
        assert_path(&fixture!("leaf"), &[issuer], true);
    }
    assert_path(&fixture!("leaf-direct"), &[], true);
}

#[test]
fn unused_restricted_or_malformed_issuers() {
    for unused in [
        fixture!("issuer-digital-signature"),
        fixture!("issuer-wrong-tag"),
        fixture!("issuer-duplicate"),
        fixture!("issuer-trailing"),
        fixture!("issuer-nonminimal-oid"),
    ] {
        // Direct anchor paths use none of the candidates, even when subjects match.
        assert_path(
            &fixture!("leaf-direct"),
            std::slice::from_ref(&unused),
            true,
        );
        assert_path_to(
            &fixture!("leaf"),
            std::slice::from_ref(&unused),
            &[fixture!("issuer-good")],
            true,
        );
        for chain in [
            vec![unused.clone(), fixture!("issuer-good")],
            vec![fixture!("issuer-good"), unused],
        ] {
            assert_path(&fixture!("leaf"), &chain, true);
        }
    }
}

#[test]
fn restricted_higher_intermediate() {
    assert_path(
        &fixture!("leaf"),
        &[
            fixture!("issuer-cross-restricted"),
            fixture!("upper-restricted"),
        ],
        false,
    );
    assert_path(
        &fixture!("leaf"),
        &[fixture!("issuer-cross-good"), fixture!("upper-good")],
        true,
    );
}

#[test]
fn cross_signed_alternative_paths() {
    for mut chain in [
        vec![
            fixture!("issuer-cross-restricted"),
            fixture!("issuer-cross-good"),
            fixture!("upper-restricted"),
            fixture!("upper-good"),
        ],
        vec![
            fixture!("upper-good"),
            fixture!("upper-restricted"),
            fixture!("issuer-cross-good"),
            fixture!("issuer-cross-restricted"),
        ],
    ] {
        assert_path(&fixture!("leaf"), &chain, true);
        chain.retain(|cert| *cert != fixture!("upper-good"));
        assert_path(&fixture!("leaf"), &chain, false);
    }
    // A signing-permitted alternative under an untrusted root cannot rescue the path.
    for chain in [
        vec![
            fixture!("issuer-digital-signature"),
            fixture!("issuer-untrusted"),
        ],
        vec![
            fixture!("issuer-untrusted"),
            fixture!("issuer-digital-signature"),
        ],
    ] {
        assert_path(&fixture!("leaf"), &chain, false);
    }
}

#[test]
fn explicit_restricted_anchor() {
    for anchor in [
        fixture!("issuer-digital-signature"),
        fixture!("issuer-crl-sign"),
    ] {
        assert_path_to(&fixture!("leaf"), &[], std::slice::from_ref(&anchor), true);
        assert_path_to(
            &fixture!("leaf"),
            std::slice::from_ref(&anchor),
            std::slice::from_ref(&anchor),
            true,
        );
    }
}

#[test]
fn existing_signature_validity_and_path_length_checks() {
    assert_path(
        &fixture!("leaf-bad-signature"),
        &[fixture!("issuer-good")],
        false,
    );
    assert_path(&fixture!("leaf-expired"), &[fixture!("issuer-good")], false);
    assert_path(
        &fixture!("leaf"),
        &[fixture!("issuer-cross-good"), fixture!("upper-pathlen")],
        false,
    );
    // Force the supplementary pass; its retained candidates must still pass all checks.
    assert_path(
        &fixture!("leaf"),
        &[
            fixture!("issuer-digital-signature"),
            fixture!("issuer-cross-good"),
            fixture!("upper-pathlen"),
        ],
        false,
    );
    assert_path(
        &fixture!("leaf"),
        &[
            fixture!("issuer-digital-signature"),
            fixture!("issuer-wrong-eku"),
        ],
        false,
    );
    assert_path(
        &fixture!("leaf-blocked-name"),
        &[fixture!("issuer-name-constraints")],
        false,
    );
    assert_path(
        &fixture!("leaf-blocked-name"),
        &[
            fixture!("issuer-digital-signature"),
            fixture!("issuer-name-constraints"),
        ],
        false,
    );
}

#[test]
fn original_path_search_failure_is_preserved() {
    let mut chain = vec![fixture!("issuer-bad-signature"); 101];
    chain.push(fixture!("issuer-good"));
    // Removing the restricted candidates first would rescue this originally
    // budget-exhausted path. Original rustls rejection must remain a rejection.
    for role in ROLES {
        let calls = Arc::new(AtomicUsize::new(0));
        let err = verify(
            role,
            &fixture!("leaf"),
            &chain,
            material(&[fixture!("root")], "example.org"),
            TrustDomainPolicy::AnyInBundleSet,
            true,
            &calls,
        )
        .unwrap_err();
        assert!(matches!(err, rustls::Error::InvalidCertificate(_)));
        assert!(
            format!("{err:?}").contains("MaximumSignatureChecksExceeded"),
            "{err:?}"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn certificate_error_mapping_is_preserved() {
    for role in ROLES {
        for (issuer, expected) in [
            (
                fixture!("issuer-digital-signature"),
                rustls::CertificateError::UnknownIssuer,
            ),
            (
                fixture!("issuer-wrong-tag"),
                rustls::CertificateError::UnknownIssuer,
            ),
        ] {
            let calls = Arc::new(AtomicUsize::new(0));
            let err = verify(
                role,
                &fixture!("leaf"),
                &[issuer],
                material(&[fixture!("root")], "example.org"),
                TrustDomainPolicy::AnyInBundleSet,
                true,
                &calls,
            )
            .unwrap_err();
            assert_eq!(err, rustls::Error::InvalidCertificate(expected));
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        }
        let calls = Arc::new(AtomicUsize::new(0));
        let err = verify(
            role,
            &fixture!("leaf"),
            &[fixture!("issuer-duplicate")],
            material(&[fixture!("root")], "example.org"),
            TrustDomainPolicy::AnyInBundleSet,
            true,
            &calls,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            rustls::Error::InvalidCertificate(rustls::CertificateError::Other(_))
        ));
        assert!(
            format!("{err:?}").contains("ExtensionValueInvalid"),
            "{err:?}"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn permitted_alternative_cannot_use_another_domains_bundle() {
    let provider = material(&[fixture!("root")], "example.org");
    let mut snapshot = (*provider.current_material().unwrap()).clone();
    let mut other_roots = rustls::RootCertStore::empty();
    other_roots.add(fixture!("root-b")).unwrap();
    snapshot
        .roots_by_td
        .insert("other.org".try_into().unwrap(), Arc::new(other_roots));
    let provider: Arc<dyn MaterialProvider> = Arc::new(StaticMaterial(Arc::new(snapshot)));
    for role in ROLES {
        let calls = Arc::new(AtomicUsize::new(0));
        let err = verify(
            role,
            &fixture!("leaf"),
            &[
                fixture!("issuer-digital-signature"),
                fixture!("issuer-untrusted"),
            ],
            Arc::clone(&provider),
            TrustDomainPolicy::AnyInBundleSet,
            true,
            &calls,
        )
        .unwrap_err();
        assert_eq!(
            err,
            rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn existing_identity_domain_and_authorization_checks() {
    for role in ROLES {
        for (leaf, domain, policy, authorized) in [
            (
                fixture!("leaf-invalid-id"),
                "example.org",
                TrustDomainPolicy::AnyInBundleSet,
                true,
            ),
            (
                fixture!("leaf-wrong-domain"),
                "other.org",
                TrustDomainPolicy::LocalOnly("example.org".try_into().unwrap()),
                true,
            ),
            (
                fixture!("leaf"),
                "other.org",
                TrustDomainPolicy::AnyInBundleSet,
                true,
            ),
            (
                fixture!("leaf"),
                "example.org",
                TrustDomainPolicy::AnyInBundleSet,
                false,
            ),
        ] {
            let calls = Arc::new(AtomicUsize::new(0));
            let err = verify(
                role,
                &leaf,
                &[fixture!("issuer-good")],
                material(&[fixture!("root")], domain),
                policy,
                authorized,
                &calls,
            )
            .unwrap_err();
            assert!(matches!(err, rustls::Error::Other(_)));
            assert_eq!(calls.load(Ordering::SeqCst), usize::from(!authorized));
        }
        let wrong_eku = match role {
            Role::Server => fixture!("leaf-client-eku"),
            Role::Client => fixture!("leaf-server-eku"),
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let err = verify(
            role,
            &wrong_eku,
            &[fixture!("issuer-good")],
            material(&[fixture!("root")], "example.org"),
            TrustDomainPolicy::AnyInBundleSet,
            true,
            &calls,
        )
        .unwrap_err();
        assert!(matches!(err, rustls::Error::InvalidCertificate(_)));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}

#[derive(Debug)]
struct FixedTime;

impl rustls::time_provider::TimeProvider for FixedTime {
    fn current_time(&self) -> Option<UnixTime> {
        Some(now())
    }
}

#[derive(Debug)]
struct ClientKey(Arc<rustls::sign::CertifiedKey>);

impl rustls::client::ResolvesClientCert for ClientKey {
    fn resolve(
        &self,
        _: &[&[u8]],
        _: &[SignatureScheme],
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }

    fn has_certs(&self) -> bool {
        true
    }
}

#[derive(Debug)]
struct ServerKey(Arc<rustls::sign::CertifiedKey>);

impl rustls::server::ResolvesServerCert for ServerKey {
    fn resolve(
        &self,
        _: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }
}

fn handshake(
    peer: Vec<CertificateDer<'static>>,
    constrained_role: Role,
    version: &'static rustls::SupportedProtocolVersion,
) -> std::result::Result<(), (Role, rustls::Error)> {
    handshake_to(peer, constrained_role, version, &[fixture!("root")])
}

#[expect(
    clippy::unwrap_in_result,
    reason = "Result carries TLS rejections; in-memory I/O and fixture failures fail the test"
)]
fn handshake_to(
    peer: Vec<CertificateDer<'static>>,
    constrained_role: Role,
    version: &'static rustls::SupportedProtocolVersion,
    anchors: &[CertificateDer<'static>],
) -> std::result::Result<(), (Role, rustls::Error)> {
    crate::crypto::ensure_crypto_provider_installed();
    let crypto = Arc::clone(rustls::crypto::CryptoProvider::get_default().unwrap());
    let trusted = material(anchors, "example.org");
    // Trust the root too so the other, valid peer remains independent of the
    // constrained peer's explicit issuer-anchor control.
    let mut anchors_with_root = anchors.to_vec();
    anchors_with_root.push(fixture!("root"));
    let other_trusted = material(&anchors_with_root, "example.org");
    let good = vec![fixture!("leaf-direct")];
    let (client_chain, server_chain) = match constrained_role {
        Role::Server => (good, peer),
        Role::Client => (peer, good),
    };
    let authorize = || crate::authorizer::exact(["spiffe://example.org/workload"]).unwrap();
    let mut client_config =
        rustls::ClientConfig::builder_with_details(Arc::clone(&crypto), Arc::new(FixedTime))
            .with_protocol_versions(&[version])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SpiffeServerCertVerifier::new(
                match constrained_role {
                    Role::Server => Arc::clone(&trusted),
                    Role::Client => Arc::clone(&other_trusted),
                },
                authorize(),
                TrustDomainPolicy::AnyInBundleSet,
            )))
            .with_client_cert_resolver(Arc::new(ClientKey(key(client_chain))));
    client_config.resumption = rustls::client::Resumption::disabled();
    let mut server_config = rustls::ServerConfig::builder_with_details(crypto, Arc::new(FixedTime))
        .with_protocol_versions(&[version])
        .unwrap()
        .with_client_cert_verifier(Arc::new(SpiffeClientCertVerifier::new(
            match constrained_role {
                Role::Client => trusted,
                Role::Server => other_trusted,
            },
            authorize(),
            TrustDomainPolicy::AnyInBundleSet,
        )))
        .with_cert_resolver(Arc::new(ServerKey(key(server_chain))));
    server_config.send_tls13_tickets = 0;
    server_config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    complete_handshake(Arc::new(client_config), Arc::new(server_config), version)
}

#[expect(
    clippy::unwrap_in_result,
    clippy::panic_in_result_fn,
    reason = "Result carries TLS rejections; in-memory I/O and fixture failures fail the test"
)]
fn complete_handshake(
    client_config: Arc<rustls::ClientConfig>,
    server_config: Arc<rustls::ServerConfig>,
    version: &'static rustls::SupportedProtocolVersion,
) -> std::result::Result<(), (Role, rustls::Error)> {
    let mut client =
        rustls::ClientConnection::new(client_config, ServerName::try_from("localhost").unwrap())
            .unwrap();
    let mut server = rustls::ServerConnection::new(server_config).unwrap();
    for _ in 0..32 {
        let mut bytes = Vec::new();
        client.write_tls(&mut bytes).unwrap();
        if !bytes.is_empty() {
            server.read_tls(&mut bytes.as_slice()).unwrap();
            server
                .process_new_packets()
                .map_err(|err| (Role::Client, err))?;
        }
        let mut bytes = Vec::new();
        server.write_tls(&mut bytes).unwrap();
        if !bytes.is_empty() {
            client.read_tls(&mut bytes.as_slice()).unwrap();
            client
                .process_new_packets()
                .map_err(|err| (Role::Server, err))?;
        }
        if !client.is_handshaking() && !server.is_handshaking() {
            assert_eq!(client.protocol_version(), Some(version.version));
            assert_eq!(server.protocol_version(), Some(version.version));
            client.writer().write_all(b"authenticated client").unwrap();
            let mut bytes = Vec::new();
            client.write_tls(&mut bytes).unwrap();
            server.read_tls(&mut bytes.as_slice()).unwrap();
            server.process_new_packets().unwrap();
            let mut received = [0; 20];
            server.reader().read_exact(&mut received).unwrap();
            assert_eq!(&received, b"authenticated client");
            server.writer().write_all(b"authenticated server").unwrap();
            let mut bytes = Vec::new();
            server.write_tls(&mut bytes).unwrap();
            client.read_tls(&mut bytes.as_slice()).unwrap();
            client.process_new_packets().unwrap();
            client.reader().read_exact(&mut received).unwrap();
            assert_eq!(&received, b"authenticated server");
            return Ok(());
        }
    }
    panic!("in-memory TLS handshake did not finish");
}

#[expect(
    clippy::too_many_lines,
    reason = "keep the protocol regression matrix together"
)]
fn handshake_matrix(version: &'static rustls::SupportedProtocolVersion) {
    for role in ROLES {
        for chain in [
            vec![fixture!("leaf"), fixture!("issuer-good")],
            vec![fixture!("leaf"), fixture!("issuer-key-cert-sign")],
            vec![fixture!("leaf"), fixture!("issuer-good-noncritical")],
            vec![fixture!("leaf"), fixture!("issuer-missing")],
            vec![fixture!("leaf-direct")],
            vec![
                fixture!("leaf-direct"),
                fixture!("issuer-digital-signature"),
                fixture!("issuer-wrong-tag"),
            ],
            vec![
                fixture!("leaf"),
                fixture!("issuer-digital-signature"),
                fixture!("issuer-good"),
            ],
            vec![
                fixture!("leaf"),
                fixture!("issuer-good"),
                fixture!("issuer-digital-signature"),
            ],
            vec![
                fixture!("leaf"),
                fixture!("issuer-wrong-tag"),
                fixture!("issuer-good"),
            ],
            vec![
                fixture!("leaf"),
                fixture!("issuer-good"),
                fixture!("issuer-wrong-tag"),
            ],
            vec![
                fixture!("leaf"),
                fixture!("issuer-cross-restricted"),
                fixture!("issuer-cross-good"),
                fixture!("upper-restricted"),
                fixture!("upper-good"),
            ],
            vec![
                fixture!("leaf"),
                fixture!("issuer-cross-good"),
                fixture!("issuer-cross-restricted"),
                fixture!("upper-good"),
                fixture!("upper-restricted"),
            ],
        ] {
            handshake(chain, role, version).unwrap();
        }
        for chain in [
            vec![fixture!("leaf")],
            vec![fixture!("leaf"), fixture!("issuer-digital-signature")],
        ] {
            handshake_to(
                chain,
                role,
                version,
                &[fixture!("issuer-digital-signature")],
            )
            .unwrap();
        }
        for issuer in [
            fixture!("issuer-digital-signature"),
            fixture!("issuer-crl-sign"),
            fixture!("issuer-noncritical"),
            fixture!("issuer-wrong-tag"),
            fixture!("issuer-duplicate"),
            fixture!("issuer-trailing"),
            fixture!("issuer-invalid-unused"),
            fixture!("issuer-invalid-padding"),
            fixture!("issuer-truncated"),
            fixture!("issuer-empty"),
            fixture!("issuer-nonminimal-bits"),
            fixture!("issuer-nonminimal-length"),
            fixture!("issuer-nonminimal-oid"),
            fixture!("issuer-undefined-bit"),
            fixture!("issuer-constructed"),
            fixture!("issuer-indefinite"),
            fixture!("issuer-not-ca"),
            fixture!("issuer-wrong-eku"),
        ] {
            let (failed_role, err) = handshake(vec![fixture!("leaf"), issuer], role, version)
                .expect_err("restricted or malformed issuer must fail TLS authentication");
            assert!(matches!(
                (role, failed_role),
                (Role::Server, Role::Server) | (Role::Client, Role::Client)
            ));
            assert!(
                matches!(err, rustls::Error::InvalidCertificate(_)),
                "{err:?}"
            );
        }
        let (failed_role, err) = handshake(
            vec![
                fixture!("leaf"),
                fixture!("issuer-cross-restricted"),
                fixture!("upper-restricted"),
            ],
            role,
            version,
        )
        .unwrap_err();
        assert!(matches!(
            (role, failed_role),
            (Role::Server, Role::Server) | (Role::Client, Role::Client)
        ));
        assert!(matches!(err, rustls::Error::InvalidCertificate(_)));
        let wrong_eku = match role {
            Role::Server => fixture!("leaf-client-eku"),
            Role::Client => fixture!("leaf-server-eku"),
        };
        for (chain, certificate_error) in [
            (
                vec![fixture!("leaf-bad-signature"), fixture!("issuer-good")],
                true,
            ),
            (
                vec![fixture!("leaf-expired"), fixture!("issuer-good")],
                true,
            ),
            (
                vec![
                    fixture!("leaf"),
                    fixture!("issuer-cross-good"),
                    fixture!("upper-pathlen"),
                ],
                true,
            ),
            (
                vec![fixture!("leaf-invalid-id"), fixture!("issuer-good")],
                false,
            ),
            // The peer's trust domain has no trusted bundle.
            (
                vec![fixture!("leaf-wrong-domain"), fixture!("issuer-good")],
                false,
            ),
            (
                vec![fixture!("leaf-unauthorized"), fixture!("issuer-good")],
                false,
            ),
            (vec![wrong_eku, fixture!("issuer-good")], true),
        ] {
            let (failed_role, err) = handshake(chain, role, version).unwrap_err();
            assert!(matches!(
                (role, failed_role),
                (Role::Server, Role::Server) | (Role::Client, Role::Client)
            ));
            if certificate_error {
                assert!(
                    matches!(err, rustls::Error::InvalidCertificate(_)),
                    "{err:?}"
                );
            } else {
                assert!(matches!(err, rustls::Error::Other(_)), "{err:?}");
            }
        }
    }
}

#[test]
fn tls13_peer_authentication() {
    handshake_matrix(&rustls::version::TLS13);
}

// The dependency feature is explicitly enabled in the TLS 1.2 validation lane.
// Using ALL_VERSIONS avoids exposing a new crate feature just for tests.
#[test]
fn tls12_peer_authentication_when_supported() {
    if let Some(version) = rustls::ALL_VERSIONS
        .iter()
        .find(|version| version.version == rustls::ProtocolVersion::TLSv1_2)
    {
        handshake_matrix(version);
    }
}
