//! Integration tests for `X509Source`.
//!
//! These tests require a running SPIRE server and agent with workloads registered
//! (see `scripts/run-spire.sh`).
//!
//! The tests cover:
//! - Basic SVID and bundle retrieval
//! - Update notifications
//! - Custom pickers and client factories
//! - Resource limits
//! - Health checks
//! - Shutdown behavior
//! - Convenience methods

#[cfg(feature = "integration-tests")]
mod integration_tests_x509_source {
    use once_cell::sync::Lazy;
    use spiffe::bundle::BundleSource;
    use spiffe::workload_api::error::WorkloadApiError;
    use spiffe::workload_api::x509_source::{SvidPicker, X509SourceBuilder};
    use spiffe::{
        MetricsErrorKind, MetricsRecorder, ResourceLimits, SpiffeId, TrustDomain,
        WorkloadApiClient, X509Bundle, X509Source, X509Svid,
    };
    use std::collections::HashMap;
    use std::error::Error;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::Mutex;

    static SPIFFE_ID_1: Lazy<SpiffeId> =
        Lazy::new(|| SpiffeId::new("spiffe://example.org/myservice").unwrap());

    static SPIFFE_ID_2: Lazy<SpiffeId> =
        Lazy::new(|| SpiffeId::new("spiffe://example.org/myservice2").unwrap());

    static TRUST_DOMAIN: Lazy<TrustDomain> = Lazy::new(|| TrustDomain::new("example.org").unwrap());

    #[derive(Debug)]
    struct SecondSvidPicker;

    impl SvidPicker for SecondSvidPicker {
        fn pick_svid(&self, svids: &[Arc<X509Svid>]) -> Option<usize> {
            if svids.len() > 1 {
                Some(1)
            } else {
                None
            }
        }
    }

    /// Test metrics recorder that tracks all recorded metrics.
    #[derive(Debug, Default)]
    struct TestMetricsRecorder {
        updates: AtomicU64,
        reconnects: AtomicU64,
        errors: Arc<Mutex<HashMap<MetricsErrorKind, u64>>>,
    }

    impl MetricsRecorder for TestMetricsRecorder {
        fn record_update(&self) {
            self.updates.fetch_add(1, Ordering::Relaxed);
        }

        fn record_reconnect(&self) {
            self.reconnects.fetch_add(1, Ordering::Relaxed);
        }

        fn record_error(&self, kind: MetricsErrorKind) {
            // Use a blocking lock since this is called from async context
            // and we need to avoid deadlocks. In a real implementation,
            // you'd use async locking, but for tests this is acceptable.
            let mut errors = self.errors.blocking_lock();
            *errors.entry(kind).or_insert(0) += 1;
        }
    }

    impl TestMetricsRecorder {
        fn new() -> Self {
            Self::default()
        }

        fn update_count(&self) -> u64 {
            self.updates.load(Ordering::Relaxed)
        }
    }

    async fn get_source() -> Arc<X509Source> {
        X509Source::new()
            .await
            .expect("Failed to create X509Source")
    }

    #[tokio::test]
    async fn test_get_x509_svid() {
        let source = get_source().await;
        let svid = source.svid().expect("Failed to get X509Svid");

        let expected_ids = [&*SPIFFE_ID_1, &*SPIFFE_ID_2];
        assert!(
            expected_ids.contains(&svid.spiffe_id()),
            "Unexpected SPIFFE ID: {:?}",
            svid.spiffe_id()
        );
        assert!(
            !svid.cert_chain().is_empty(),
            "Certificate chain should not be empty"
        );
    }

    #[tokio::test]
    async fn test_try_svid() {
        let source = get_source().await;

        // Should succeed when source is healthy
        let svid = source
            .try_svid()
            .expect("try_svid() should return Some when healthy");
        assert!(
            [&*SPIFFE_ID_1, &*SPIFFE_ID_2].contains(&svid.spiffe_id()),
            "Unexpected SPIFFE ID"
        );

        // After shutdown, should return None
        source.shutdown().await;
        assert!(
            source.try_svid().is_none(),
            "try_svid() should return None after shutdown"
        );
    }

    #[tokio::test]
    async fn test_get_bundle_for_trust_domain() {
        let source = get_source().await;
        let bundle: Arc<X509Bundle> = source
            .bundle_for_trust_domain(&TRUST_DOMAIN)
            .expect("Failed to get X509Bundle")
            .expect("No X509Bundle found");

        assert_eq!(bundle.trust_domain().as_ref(), TRUST_DOMAIN.as_ref());
        assert!(
            !bundle.authorities().is_empty(),
            "Bundle should have at least one authority"
        );
    }

    #[tokio::test]
    async fn test_try_bundle_for_trust_domain() {
        let source = get_source().await;

        // Should succeed when source is healthy
        let bundle = source
            .try_bundle_for_trust_domain(&TRUST_DOMAIN)
            .expect("try_bundle_for_trust_domain() should return Some when healthy");
        assert_eq!(bundle.trust_domain().as_ref(), TRUST_DOMAIN.as_ref());

        // After shutdown, should return None
        source.shutdown().await;
        assert!(
            source.try_bundle_for_trust_domain(&TRUST_DOMAIN).is_none(),
            "try_bundle_for_trust_domain() should return None after shutdown"
        );
    }

    #[tokio::test]
    async fn test_bundle_set() {
        let source = get_source().await;
        let bundle_set = source.bundle_set().expect("Failed to get bundle set");

        let bundle = bundle_set.get(&TRUST_DOMAIN);
        assert!(bundle.is_some(), "Bundle set should contain trust domain");
        assert_eq!(
            bundle.unwrap().trust_domain().as_ref(),
            TRUST_DOMAIN.as_ref()
        );
    }

    #[tokio::test]
    async fn test_x509_context() {
        let source = get_source().await;
        let context = source.x509_context().expect("Failed to get X509Context");

        // Should have at least one SVID
        assert!(
            !context.svids().is_empty(),
            "Context should have at least one SVID"
        );

        // Should have a default SVID
        let default_svid = context.default_svid();
        assert!(default_svid.is_some(), "Context should have a default SVID");

        // Should have bundles
        assert!(
            !context.bundle_set().is_empty(),
            "Context should have bundles"
        );
    }

    #[tokio::test]
    async fn test_is_healthy() {
        let source = get_source().await;

        // Should be healthy when source is active
        assert!(
            source.is_healthy(),
            "Source should be healthy after creation"
        );

        // If healthy, svid() should succeed
        if source.is_healthy() {
            let svid_result = source.svid();
            assert!(
                svid_result.is_ok(),
                "If is_healthy() returns true, svid() should succeed"
            );
        }

        // After shutdown, should be unhealthy
        source.shutdown().await;
        assert!(
            !source.is_healthy(),
            "Source should be unhealthy after shutdown"
        );
    }

    #[tokio::test]
    async fn test_source_updates() {
        let source = get_source().await;
        let mut updates = source.updated();

        // Wait for initial update (sequence number > 0)
        let initial_seq = updates.last();
        tokio::time::timeout(
            Duration::from_secs(10),
            updates.wait_for(|&seq| seq > initial_seq),
        )
        .await
        .expect("Should receive initial update within 10 seconds")
        .expect("Update channel should not be closed");

        // Verify we got an update
        let new_seq = updates.last();
        assert!(
            new_seq > initial_seq,
            "Sequence number should have increased"
        );
    }

    #[tokio::test]
    async fn test_x509_source_with_custom_picker_and_client() -> Result<(), Box<dyn Error>> {
        type ClientFactory = Arc<
            dyn Fn() -> Pin<
                    Box<dyn Future<Output = Result<WorkloadApiClient, WorkloadApiError>> + Send>,
                > + Send
                + Sync,
        >;

        let factory: ClientFactory =
            Arc::new(|| Box::pin(async { WorkloadApiClient::connect_env().await }));

        let source = X509SourceBuilder::new()
            .with_client_factory(factory)
            .with_picker(SecondSvidPicker)
            .build()
            .await?;

        let svid = source.svid().expect("Failed to get X509Svid");

        let expected_ids = [&*SPIFFE_ID_1, &*SPIFFE_ID_2];
        assert!(
            expected_ids.contains(&svid.spiffe_id()),
            "Unexpected SPIFFE ID"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_resource_limits() -> Result<(), Box<dyn Error>> {
        // Test with very restrictive limits (should still work if actual values are below limits)
        let limits = ResourceLimits {
            max_svids: Some(10),
            max_bundles: Some(10),
            max_bundle_der_bytes: Some(1024 * 1024), // 1MB
        };

        let source = X509SourceBuilder::new()
            .with_resource_limits(limits)
            .build()
            .await?;

        // Should work if limits are not exceeded
        let svid = source.svid()?;
        assert!(
            [&*SPIFFE_ID_1, &*SPIFFE_ID_2].contains(&svid.spiffe_id()),
            "Should get SVID when limits are not exceeded"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_unlimited_resource_limits() -> Result<(), Box<dyn Error>> {
        // Test with unlimited limits
        let limits = ResourceLimits {
            max_svids: None,
            max_bundles: None,
            max_bundle_der_bytes: None,
        };

        let source = X509SourceBuilder::new()
            .with_resource_limits(limits)
            .build()
            .await?;

        // Should work with unlimited limits
        let svid = source.svid()?;
        assert!(
            [&*SPIFFE_ID_1, &*SPIFFE_ID_2].contains(&svid.spiffe_id()),
            "Should get SVID with unlimited limits"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_metrics_recorder() -> Result<(), Box<dyn Error>> {
        let metrics = Arc::new(TestMetricsRecorder::new());

        let source = X509SourceBuilder::new()
            .with_metrics(metrics.clone())
            .build()
            .await?;

        // Trigger an update by getting the SVID
        let _svid = source.svid()?;

        // Wait a bit for any background updates
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Should have recorded at least one update (initial sync)
        assert!(
            metrics.update_count() > 0,
            "Should have recorded at least one update"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_shutdown_with_timeout() -> Result<(), Box<dyn Error>> {
        let source = X509SourceBuilder::new()
            .with_shutdown_timeout(Some(Duration::from_secs(5)))
            .build()
            .await?;

        // Shutdown should complete within timeout
        let result =
            tokio::time::timeout(Duration::from_secs(10), source.shutdown_configured()).await;

        assert!(result.is_ok(), "Shutdown should complete");
        result.unwrap().expect("Shutdown should succeed");

        // After shutdown, operations should fail
        assert!(source.svid().is_err(), "svid() should fail after shutdown");

        Ok(())
    }

    #[tokio::test]
    async fn test_shutdown_idempotent() -> Result<(), Box<dyn Error>> {
        let source = X509SourceBuilder::new()
            .with_shutdown_timeout(Some(Duration::from_secs(5)))
            .build()
            .await?;

        // First shutdown
        source.shutdown_configured().await?;

        // Second shutdown should also succeed (idempotent)
        let result = source.shutdown_configured().await;
        assert!(result.is_ok(), "Shutdown should be idempotent");

        Ok(())
    }

    #[tokio::test]
    async fn test_reconnect_backoff_config() -> Result<(), Box<dyn Error>> {
        let source = X509SourceBuilder::new()
            .with_reconnect_backoff(Duration::from_millis(100), Duration::from_secs(5))
            .build()
            .await?;

        // Should work with custom backoff
        let svid = source.svid()?;
        assert!(
            [&*SPIFFE_ID_1, &*SPIFFE_ID_2].contains(&svid.spiffe_id()),
            "Should get SVID with custom backoff config"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_custom_endpoint() -> Result<(), Box<dyn Error>> {
        // Test that custom endpoint configuration works
        // This will use the default endpoint from environment if custom endpoint fails
        let source = X509SourceBuilder::new()
            .with_endpoint("unix:/tmp/spire-agent/public/api.sock")
            .build()
            .await?;

        let svid = source.svid()?;
        assert!(
            [&*SPIFFE_ID_1, &*SPIFFE_ID_2].contains(&svid.spiffe_id()),
            "Should get SVID with custom endpoint"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_picker_selection() -> Result<(), Box<dyn Error>> {
        // Test that picker actually selects the second SVID
        let source = X509SourceBuilder::new()
            .with_picker(SecondSvidPicker)
            .build()
            .await?;

        let svid = source.svid()?;
        // The picker selects the second SVID (index 1)
        // We can't assert the exact ID without knowing the order, but we can verify it works
        assert!(
            [&*SPIFFE_ID_1, &*SPIFFE_ID_2].contains(&svid.spiffe_id()),
            "Picker should select a valid SVID"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_health_check_guarantees_svid_success() {
        let source = get_source().await;

        // If is_healthy() returns true, svid() must succeed
        if source.is_healthy() {
            let svid_result = source.svid();
            assert!(
                svid_result.is_ok(),
                "is_healthy() returning true must guarantee svid() succeeds"
            );
        }

        // Test multiple times to ensure consistency
        for _ in 0..10 {
            if source.is_healthy() {
                assert!(
                    source.svid().is_ok(),
                    "is_healthy() must consistently guarantee svid() success"
                );
            }
        }
    }

    #[tokio::test]
    async fn test_update_notifications_sequence() {
        let source = get_source().await;
        let mut updates = source.updated();

        // Get initial sequence number
        let initial_seq = updates.last();

        // Wait for at least one update
        tokio::time::timeout(
            Duration::from_secs(30),
            updates.wait_for(|&seq| seq > initial_seq),
        )
        .await
        .expect("Should receive update within 30 seconds")
        .expect("Update channel should not be closed");

        // Sequence should have increased
        let new_seq = updates.last();
        assert!(new_seq > initial_seq, "Sequence number should increase");

        // Sequence numbers should be monotonic
        assert!(
            new_seq >= initial_seq,
            "Sequence numbers should be monotonic"
        );
    }

    #[tokio::test]
    async fn test_multiple_update_receivers() {
        let source = get_source().await;
        let mut updates1 = source.updated();
        let updates2 = source.updated();

        let initial_seq1 = updates1.last();
        let initial_seq2 = updates2.last();

        // Both should start with the same sequence
        assert_eq!(
            initial_seq1, initial_seq2,
            "Receivers should start with same sequence"
        );

        // Wait for update on one receiver
        tokio::time::timeout(
            Duration::from_secs(30),
            updates1.wait_for(|&seq| seq > initial_seq1),
        )
        .await
        .expect("Should receive update")
        .expect("Update channel should not be closed");

        // Both receivers should see the update
        assert_eq!(
            updates1.last(),
            updates2.last(),
            "All receivers should see the same sequence number"
        );
    }

    #[tokio::test]
    async fn test_builder_defaults() -> Result<(), Box<dyn Error>> {
        // Test that builder with defaults works
        let source = X509SourceBuilder::new().build().await?;

        let svid = source.svid()?;
        assert!(
            [&*SPIFFE_ID_1, &*SPIFFE_ID_2].contains(&svid.spiffe_id()),
            "Should work with default builder configuration"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_context_after_shutdown() {
        let source = get_source().await;
        source.shutdown().await;

        // After shutdown, context operations should fail
        assert!(
            source.x509_context().is_err(),
            "x509_context() should fail after shutdown"
        );
        assert!(
            source.bundle_set().is_err(),
            "bundle_set() should fail after shutdown"
        );
    }

    #[tokio::test]
    async fn test_updated_after_shutdown() {
        let source = get_source().await;
        let updates = source.updated();

        // Shutdown the source
        source.shutdown().await;

        // Receiver should still be valid (watch channels don't close on sender drop)
        // But we can't receive new updates
        let seq_before = updates.last();

        // Wait a bit - no new updates should come
        tokio::time::sleep(Duration::from_millis(100)).await;

        let seq_after = updates.last();
        assert_eq!(
            seq_before, seq_after,
            "Sequence should not change after shutdown"
        );
    }
}
