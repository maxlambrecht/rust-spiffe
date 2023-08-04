// These tests need a SPIFFE implementation running, thus they are ignored by default,
// to run them use: `cargo test -- --include-ignored`

use spiffe::bundle::BundleRefSource;
use spiffe::spiffe_id::TrustDomain;
use spiffe::workload_api::client::WorkloadApiClient;

#[tokio::test]
#[ignore]
async fn fetch_jwt_svid() {
    let client = WorkloadApiClient::default().await.unwrap();
    let svid = client.fetch_jwt_svid(&["my_audience"], None).await.unwrap();
    assert_eq!(svid.audience(), &["my_audience"]);
}

#[tokio::test]
#[ignore]
async fn fetch_and_validate_jwt_token() {
    let client = WorkloadApiClient::default().await.unwrap();
    let token = client.clone().fetch_jwt_token(&["my_audience"], None).await.unwrap();
    let jwt_svid = client.clone().validate_jwt_token("my_audience", &token).await.unwrap();
    assert_eq!(jwt_svid.audience(), &["my_audience"]);
    assert_eq!(
        jwt_svid.spiffe_id().to_string(),
        "spiffe://example.org/myservice"
    );
}

#[tokio::test]
#[ignore]
async fn fetch_jwt_bundles() {
    let client = WorkloadApiClient::default().await.unwrap();
    let bundles = client.clone().fetch_jwt_bundles().await.unwrap();

    let bundle = bundles.get_bundle_for_trust_domain(&TrustDomain::new("example.org").unwrap());
    let bundle = bundle.unwrap().unwrap();

    let svid = client.fetch_jwt_svid(&["my_audience"], None).await.unwrap();
    let key_id = svid.key_id();

    assert_eq!(bundle.trust_domain().to_string(), "example.org");
    assert_eq!(
        bundle.find_jwt_authority(key_id).unwrap().key_id,
        Some(key_id.to_string())
    );
}

#[tokio::test]
#[ignore]
async fn fetch_x509_svid() {
    let client = WorkloadApiClient::default().await.unwrap();
    let svid = client.fetch_x509_svid().await.unwrap();
    assert_eq!(
        svid.spiffe_id().to_string(),
        "spiffe://example.org/myservice"
    );

    assert_eq!(svid.cert_chain().len(), 1);
}

#[tokio::test]
#[ignore]
async fn fetch_x509_context() {
    let client = WorkloadApiClient::default().await.unwrap();
    let x509_context = client.fetch_x509_context().await.unwrap();

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

#[tokio::test]
#[ignore]
async fn fetch_x509_bundles() {
    let client = WorkloadApiClient::default().await.unwrap();
    let bundles = client.fetch_x509_bundles().await.unwrap();

    let bundle = bundles.get_bundle_for_trust_domain(&TrustDomain::new("example.org").unwrap());
    let bundle = bundle.unwrap().unwrap();

    assert_eq!(bundle.trust_domain().to_string(), "example.org");
    assert_eq!(bundle.authorities().len(), 1);
}
