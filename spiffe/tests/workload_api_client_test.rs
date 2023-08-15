// These tests requires a running SPIRE server and agent with workloads registered (see `scripts/run-spire.sh`).

#[cfg(feature = "integration-tests")]
mod integration_tests {
    use once_cell::sync::Lazy;
    use spiffe::bundle::BundleRefSource;
    use spiffe::spiffe_id::{SpiffeId, TrustDomain};
    use spiffe::workload_api::client::WorkloadApiClient;
    use tokio_stream::StreamExt;

    static SPIFFE_ID_1: Lazy<SpiffeId> =
        Lazy::new(|| SpiffeId::new("spiffe://example.org/myservice").unwrap());

    static SPIFFE_ID_2: Lazy<SpiffeId> =
        Lazy::new(|| SpiffeId::new("spiffe://example.org/myservice2").unwrap());

    static TRUST_DOMAIN: Lazy<TrustDomain> = Lazy::new(|| TrustDomain::new("example.org").unwrap());

    async fn get_client() -> WorkloadApiClient {
        WorkloadApiClient::default()
            .await
            .expect("Failed to create client")
    }

    #[tokio::test]
    async fn fetch_jwt_svid() {
        let mut client = get_client().await;
        let svid = client
            .fetch_jwt_svid(&["my_audience"], None)
            .await
            .expect("Failed to fetch JWT SVID");
        assert_eq!(svid.audience(), &["my_audience"]);
    }

    #[tokio::test]
    async fn fetch_and_validate_jwt_token() {
        let mut client = get_client().await;

        let token = client
            .fetch_jwt_token(&["my_audience"], Some(&*SPIFFE_ID_1))
            .await
            .expect("Failed to fetch JWT token");
        let jwt_svid = client
            .validate_jwt_token("my_audience", &token)
            .await
            .expect("Failed to validate JWT token");
        assert_eq!(jwt_svid.audience(), &["my_audience"]);
        assert_eq!(jwt_svid.spiffe_id(), &*SPIFFE_ID_1);

        let token = client
            .fetch_jwt_token(&["other_audience"], Some(&*SPIFFE_ID_2))
            .await
            .expect("Failed to fetch JWT token");
        let jwt_svid = client
            .validate_jwt_token("other_audience", &token)
            .await
            .expect("Failed to validate JWT token");
        assert_eq!(jwt_svid.audience(), &["other_audience"]);
        assert_eq!(jwt_svid.spiffe_id(), &*SPIFFE_ID_2);
    }

    #[tokio::test]
    async fn fetch_jwt_bundles() {
        let mut client = get_client().await;
        let bundles = client
            .fetch_jwt_bundles()
            .await
            .expect("Failed to fetch JWT bundles");

        let bundle = bundles.get_bundle_for_trust_domain(&*TRUST_DOMAIN);
        let bundle = bundle
            .expect("Bundle was None")
            .expect("Failed to unwrap bundle");

        let svid = client
            .fetch_jwt_svid(&["my_audience"], None)
            .await
            .expect("Failed to fetch JWT SVID");
        let key_id = svid.key_id();

        assert_eq!(bundle.trust_domain(), &*TRUST_DOMAIN);
        assert_eq!(
            bundle.find_jwt_authority(key_id).unwrap().key_id,
            Some(key_id.to_string())
        );
    }

    #[tokio::test]
    async fn fetch_x509_svid() {
        let mut client = get_client().await;
        let svid = client
            .fetch_x509_svid()
            .await
            .expect("Failed to fetch X509 SVID");

        let expected_ids = vec![&*SPIFFE_ID_1, &*SPIFFE_ID_2];
        assert!(
            expected_ids.contains(&svid.spiffe_id()),
            "Unexpected SPIFFE ID"
        );
        assert_eq!(svid.cert_chain().len(), 1);
    }

    #[tokio::test]
    async fn fetch_all_x509_svids() {
        let mut client = get_client().await;
        let svids = client
            .fetch_all_x509_svids()
            .await
            .expect("Failed to fetch X509 SVID");

        assert_eq!(svids.len(), 2, "Expected exactly two SVIDs");

        let expected_ids = vec![&*SPIFFE_ID_1, &*SPIFFE_ID_2];

        // Checking the first SVID
        let first_svid = &svids[0];
        assert!(
            expected_ids.contains(&first_svid.spiffe_id()),
            "Unexpected SPIFFE ID"
        );
        assert_eq!(first_svid.cert_chain().len(), 1);

        // Checking the second SVID
        let second_svid = &svids[1];
        assert!(
            expected_ids.contains(&second_svid.spiffe_id()),
            "Unexpected SPIFFE ID"
        );
        assert_eq!(second_svid.cert_chain().len(), 1);

        assert_ne!(
            first_svid.spiffe_id(),
            second_svid.spiffe_id(),
            "Expected different SPIFFE IDs"
        );
    }

    #[tokio::test]
    async fn fetch_x509_context() {
        let mut client = get_client().await;
        let x509_context = client
            .fetch_x509_context()
            .await
            .expect("Failed to fetch X509 context");

        let expected_ids = vec![&*SPIFFE_ID_1, &*SPIFFE_ID_2];

        let svid = x509_context.default_svid().unwrap();
        assert!(
            expected_ids.contains(&svid.spiffe_id()),
            "Unexpected SPIFFE ID"
        );
        assert_eq!(svid.cert_chain().len(), 1);

        let bundle = x509_context
            .bundle_set()
            .get_bundle_for_trust_domain(&*TRUST_DOMAIN);
        let bundle = bundle
            .expect("Bundle was None")
            .expect("Failed to unwrap bundle");

        assert_eq!(bundle.trust_domain(), &*TRUST_DOMAIN);
        assert_eq!(bundle.authorities().len(), 1);
    }

    #[tokio::test]
    async fn fetch_x509_bundles() {
        let mut client = get_client().await;
        let bundles = client
            .fetch_x509_bundles()
            .await
            .expect("Failed to fetch X509 bundles");

        let bundle = bundles.get_bundle_for_trust_domain(&*TRUST_DOMAIN);
        let bundle = bundle
            .expect("Bundle was None")
            .expect("Failed to unwrap bundle");

        assert_eq!(bundle.trust_domain(), &*TRUST_DOMAIN);
        assert_eq!(bundle.authorities().len(), 1);
    }

    #[tokio::test]
    async fn stream_x509_contexts() {
        let mut client = get_client().await;
        let test_duration = std::time::Duration::from_secs(60);
        let expected_ids = vec![&*SPIFFE_ID_1, &*SPIFFE_ID_2];

        let result = tokio::time::timeout(test_duration, async {
            let mut update_count = 0;
            let mut stream = client
                .stream_x509_contexts()
                .await
                .expect("Failed to get stream");

            while let Some(update) = stream.next().await {
                match update {
                    Ok(x509_context) => {
                        let svid = x509_context.default_svid().unwrap();
                        assert!(
                            expected_ids.contains(&svid.spiffe_id()),
                            "Unexpected SPIFFE ID"
                        );
                        assert_eq!(svid.cert_chain().len(), 1);

                        let bundle = x509_context
                            .bundle_set()
                            .get_bundle_for_trust_domain(&*TRUST_DOMAIN);
                        let bundle = bundle
                            .expect("Bundle was None")
                            .expect("Failed to unwrap bundle");

                        assert_eq!(bundle.trust_domain(), &*TRUST_DOMAIN);
                        assert_eq!(bundle.authorities().len(), 1);

                        update_count += 1;
                        if update_count == 3 {
                            break;
                        }
                    }
                    Err(e) => eprintln!("Error in stream: {:?}", e),
                }
            }

            assert_eq!(update_count, 3, "Expected 3 updates from the stream");
        })
        .await;

        assert!(
            result.is_ok(),
            "Test did not complete in the expected duration"
        );
    }

    #[tokio::test]
    async fn stream_x509_svids() {
        let mut client = get_client().await;
        let test_duration = std::time::Duration::from_secs(60);
        let expected_ids = vec![&*SPIFFE_ID_1, &*SPIFFE_ID_2];

        let result = tokio::time::timeout(test_duration, async {
            let mut update_count = 0;
            let mut stream = client
                .stream_x509_svids()
                .await
                .expect("Failed to get stream");

            while let Some(update) = stream.next().await {
                match update {
                    Ok(svid) => {
                        assert!(
                            expected_ids.contains(&svid.spiffe_id()),
                            "Unexpected SPIFFE ID"
                        );
                        assert_eq!(svid.cert_chain().len(), 1);

                        update_count += 1;
                        if update_count == 3 {
                            break;
                        }
                    }
                    Err(e) => eprintln!("Error in stream: {:?}", e),
                }
            }

            assert_eq!(update_count, 3, "Expected 3 updates from the stream");
        })
        .await;

        assert!(
            result.is_ok(),
            "Test did not complete in the expected duration"
        );
    }

    #[tokio::test]
    async fn stream_x509_bundles() {
        let mut client = get_client().await;
        let test_duration = std::time::Duration::from_secs(60);

        let result = tokio::time::timeout(test_duration, async {
            let mut stream = client
                .stream_x509_bundles()
                .await
                .expect("Failed to get stream");
            if let Some(update) = stream.next().await {
                match update {
                    Ok(bundles) => {
                        let bundle = bundles.get_bundle_for_trust_domain(&*TRUST_DOMAIN);
                        let bundle = bundle
                            .expect("Bundle was None")
                            .expect("Failed to unwrap bundle");

                        assert_eq!(bundle.trust_domain(), &*TRUST_DOMAIN);
                        assert_eq!(bundle.authorities().len(), 1);
                    }
                    Err(e) => eprintln!("Error in stream: {:?}", e),
                }
            }
        })
        .await;

        assert!(
            result.is_ok(),
            "Test did not complete in the expected duration"
        );
    }

    #[tokio::test]
    async fn stream_jwt_bundles() {
        let mut client = get_client().await;
        let test_duration = std::time::Duration::from_secs(60);

        let result = tokio::time::timeout(test_duration, async {
            let mut stream = client
                .stream_jwt_bundles()
                .await
                .expect("Failed to get stream");
            if let Some(update) = stream.next().await {
                match update {
                    Ok(bundles) => {
                        let bundle = bundles.get_bundle_for_trust_domain(&*TRUST_DOMAIN);
                        let bundle = bundle
                            .expect("Bundle was None")
                            .expect("Failed to unwrap bundle");

                        let svid = client
                            .fetch_jwt_svid(&["my_audience"], None)
                            .await
                            .expect("Failed to fetch JWT SVID");
                        let key_id = svid.key_id();

                        assert_eq!(bundle.trust_domain(), &*TRUST_DOMAIN);
                        assert_eq!(
                            bundle.find_jwt_authority(key_id).unwrap().key_id,
                            Some(key_id.to_string())
                        );
                    }
                    Err(e) => eprintln!("Error in stream: {:?}", e),
                }
            }
        })
        .await;

        assert!(
            result.is_ok(),
            "Test did not complete in the expected duration"
        );
    }
}
