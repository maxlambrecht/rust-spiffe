// These tests requires a running SPIRE server and agent with workloads registered (see `scripts/run-spire.sh`).

#[cfg(feature = "integration-tests")]
mod integration_tests_x509_source {
    use once_cell::sync::Lazy;
    use spiffe::error::GrpcClientError;
    use spiffe::workload_api::x509_source::{SvidPicker, X509SourceBuilder};
    use spiffe::{
        BundleSource, SpiffeId, SvidSource, TrustDomain, WorkloadApiClient, X509Bundle, X509Source,
        X509Svid,
    };
    use std::error::Error;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;

    static SPIFFE_ID_1: Lazy<SpiffeId> =
        Lazy::new(|| SpiffeId::new("spiffe://example.org/myservice").unwrap());

    static SPIFFE_ID_2: Lazy<SpiffeId> =
        Lazy::new(|| SpiffeId::new("spiffe://example.org/myservice2").unwrap());

    static TRUST_DOMAIN: Lazy<TrustDomain> = Lazy::new(|| TrustDomain::new("example.org").unwrap());

    #[derive(Debug)]
    struct SecondSvidPicker;

    impl SvidPicker for SecondSvidPicker {
        fn pick_svid<'a>(&self, svids: &'a [X509Svid]) -> Option<&'a X509Svid> {
            svids.get(1)
        }
    }

    async fn get_source() -> Arc<X509Source> {
        X509Source::new()
            .await
            .expect("Failed to create X509Source")
    }

    async fn get_client() -> WorkloadApiClient {
        WorkloadApiClient::default()
            .await
            .expect("Failed to create client")
    }

    #[tokio::test]
    async fn get_x509_svid() {
        let source = get_source().await;
        let svid = source
            .get_svid()
            .expect("Failed to get X509Svid")
            .expect("No X509Svid found");

        let expected_ids = vec![&*SPIFFE_ID_1, &*SPIFFE_ID_2];
        assert!(
            expected_ids.contains(&svid.spiffe_id()),
            "Unexpected SPIFFE ID"
        );
        assert_eq!(svid.cert_chain().len(), 1);
    }

    #[tokio::test]
    async fn get_bundle_for_trust_domain() {
        let source = get_source().await;
        let bundle: X509Bundle = source
            .get_bundle_for_trust_domain(&*TRUST_DOMAIN)
            .expect("Failed to get X509Bundle")
            .expect("No X509Bundle found");

        assert_eq!(bundle.trust_domain(), &*TRUST_DOMAIN);
        assert_eq!(bundle.authorities().len(), 1);
    }

    #[tokio::test]
    async fn source_updates() {
        let source = get_source().await;
        let test_duration = std::time::Duration::from_secs(60);
        let mut update_channel = source.updated();

        let result = tokio::time::timeout(test_duration, async {
            let mut update_count = 0;

            // Asynchronously handle updates
            while update_count < 3 {
                match update_channel.changed().await {
                    Ok(_) => {
                        update_count += 1;
                    }
                    Err(_) => {
                        break;
                    }
                }
            }

            assert_eq!(update_count, 3, "Expected 3 updates from the source");
        })
        .await;

        assert!(
            result.is_ok(),
            "Test did not complete in the expected duration"
        );
    }

    #[tokio::test]
    async fn test_x509_source_with_custom_picker_and_client() -> Result<(), Box<dyn Error>> {
        let picker = Box::new(SecondSvidPicker);

        let factory = Arc::new(|| -> Pin<Box<dyn Future<Output = Result<WorkloadApiClient, GrpcClientError>> + Send>> {
            Box::pin(async {
                WorkloadApiClient::default().await
            })
        });

        let source = X509SourceBuilder::new()
            .with_client_factory(factory)
            .with_picker(picker)
            .build()
            .await?;

        let svid = source
            .get_svid()
            .expect("Failed to get X509Svid")
            .expect("No X509Svid found");

        let expected_ids = vec![&*SPIFFE_ID_1, &*SPIFFE_ID_2];
        assert!(
            expected_ids.contains(&svid.spiffe_id()),
            "Unexpected SPIFFE ID"
        );

        Ok(())
    }
}
