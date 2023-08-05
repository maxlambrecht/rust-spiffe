// These tests need a SPIFFE implementation running, thus they are ignored by default,
// to run them use: `cargo test -- --include-ignored`

use spiffe::bundle::BundleRefSource;
use spiffe::spiffe_id::TrustDomain;
use spiffe::workload_api::client::WorkloadApiClient;
use spiffe::workload_api::x509_context::X509Context;

#[test]
#[ignore]
fn fetch_jwt_svid() {
    let client = WorkloadApiClient::default().unwrap();
    let svid = client.fetch_jwt_svid(&["my_audience"], None).unwrap();
    assert_eq!(svid.audience(), &["my_audience"]);
}

#[test]
#[ignore]
fn fetch_and_validate_jwt_token() {
    let client = WorkloadApiClient::default().unwrap();
    let token = client.fetch_jwt_token(&["my_audience"], None).unwrap();
    let jwt_svid = client.validate_jwt_token("my_audience", &token).unwrap();
    assert_eq!(jwt_svid.audience(), &["my_audience"]);
    assert_eq!(
        jwt_svid.spiffe_id().to_string(),
        "spiffe://example.org/myservice"
    );
}

#[test]
#[ignore]
fn fetch_jwt_bundles() {
    let client = WorkloadApiClient::default().unwrap();
    let bundles = client.fetch_jwt_bundles().unwrap();

    let bundle = bundles.get_bundle_for_trust_domain(&TrustDomain::new("example.org").unwrap());
    let bundle = bundle.unwrap().unwrap();

    let svid = client.fetch_jwt_svid(&["my_audience"], None).unwrap();
    let key_id = svid.key_id();

    assert_eq!(bundle.trust_domain().to_string(), "example.org");
    assert_eq!(
        bundle.find_jwt_authority(key_id).unwrap().key_id,
        Some(key_id.to_string())
    );
}

#[test]
#[ignore]
fn fetch_x509_svid() {
    let client = WorkloadApiClient::default().unwrap();
    let svid = client.fetch_x509_svid().unwrap();
    assert_eq!(
        svid.spiffe_id().to_string(),
        "spiffe://example.org/myservice"
    );

    assert_eq!(svid.cert_chain().len(), 1);
}

#[test]
#[ignore]
fn fetch_x509_context() {
    let client = WorkloadApiClient::default().unwrap();
    let x509_context = client.fetch_x509_context().unwrap();
    validate_x509_context(&x509_context);
}

#[test]
#[ignore]
fn fetch_x509_bundles() {
    let client = WorkloadApiClient::default().unwrap();
    let bundles = client.fetch_x509_bundles().unwrap();

    let bundle = bundles.get_bundle_for_trust_domain(&TrustDomain::new("example.org").unwrap());
    let bundle = bundle.unwrap().unwrap();

    assert_eq!(bundle.trust_domain().to_string(), "example.org");
    assert_eq!(bundle.authorities().len(), 1);
}

#[test]
#[ignore]
fn watch_x509_context_stream() {
    use futures::StreamExt;

    let client = WorkloadApiClient::default().unwrap();
    let mut x509_context_stream = client.watch_x509_context_stream().unwrap();

    let mut updates_received = 0;
    while updates_received < 3 {
        match tokio_test::block_on(x509_context_stream.next()) {
            Some(Ok(x509_context)) => {
                assert!(x509_context.svids().len() > 0);
                updates_received += 1;
                validate_x509_context(&x509_context);
            }
            Some(Err(e)) => panic!("Error occurred while watching X509Context: {:?}", e),
            None => panic!("X509Context stream ended unexpectedly"),
        };
    }
}

fn validate_x509_context(x509_context: &X509Context) {
    let svid = x509_context.default_svid().unwrap();
    assert_eq!(
        svid.spiffe_id().to_string(),
        "spiffe://example.org/myservice"
    );
    assert_eq!(svid.cert_chain().len(), 1);

    let bundle = x509_context
        .bundle_set()
        .get_bundle_for_trust_domain(&TrustDomain::new("example.org").unwrap());
    let bundle = bundle.unwrap().unwrap();

    assert_eq!(bundle.trust_domain().to_string(), "example.org");
    assert_eq!(bundle.authorities().len(), 1);
}
