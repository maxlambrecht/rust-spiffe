// These tests suppose a SPIFFE implementation is running.

use spiffe::workload_api::client::WorkloadApiClient;

#[test]
fn fetch_jwt_svid() {
    let client = WorkloadApiClient::default().unwrap();
    let svid = client.fetch_jwt_svid(&["my_audience"], None).unwrap();
    assert_eq!(svid.audience(), &["my_audience"]);
}

#[test]
fn fetch_and_validate_jwt_token() {
    let client = WorkloadApiClient::default().unwrap();
    let token = client.fetch_jwt_token(&["my_audience"], None).unwrap();
    let (spiffe_id, claims) = client.validate_jwt_token("my_audience", &token).unwrap();
    assert_eq!(claims.unwrap().get_aud(), &["my_audience"]);
    assert_eq!(spiffe_id.to_string(), "spiffe://example.org/myservice");
}
