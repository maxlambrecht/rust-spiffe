#![expect(missing_docs, reason = "integration test")]
#![expect(
    unused_crate_dependencies,
    reason = "used in library or generated wire module"
)]
#[cfg(test)]
mod probes {
    mod path_rotation {
        include!("support/integrated_path_rotation.rs");
    }
    use futures::Stream;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use std::{
        collections::HashMap,
        io::{Cursor, Read as _, Write as _},
        sync::Arc,
        time::Duration,
    };
    use tokio::sync::{mpsc, watch};
    mod wire {
        include!("support/workload_wire.rs");
    }
    use wire::{
        JwtBundlesRequest, JwtBundlesResponse, X509svid, X509svidRequest, X509svidResponse,
    };
    const A: &[u8] = include_bytes!("fixtures/withdrawal/a.der");
    const B: &[u8] = include_bytes!("fixtures/withdrawal/b.der");
    const OTHER: &[u8] = include_bytes!("fixtures/withdrawal/other.der");
    const FOREIGN: &[u8] = include_bytes!("fixtures/withdrawal/foreign.der");
    const KA: &[u8] = include_bytes!("fixtures/withdrawal/a.pkcs8");
    const KB: &[u8] = include_bytes!("fixtures/withdrawal/b.pkcs8");
    const UNSUPPORTED: &[u8] = include_bytes!("fixtures/withdrawal/unsupported.pkcs8");
    const CA: &[u8] = include_bytes!("fixtures/withdrawal/a-ca.der");
    const CB: &[u8] = include_bytes!("fixtures/withdrawal/b-ca.der");
    const EXPIRED: &[u8] = include_bytes!("fixtures/withdrawal/expired-svid-chain.der");
    const EXPIRED_KEY: &[u8] = include_bytes!("fixtures/withdrawal/expired-key.der");
    fn ensure_provider() {
        #[cfg(feature = "ring")]
        let _previous = rustls::crypto::ring::default_provider().install_default();
        #[cfg(feature = "aws-lc-rs")]
        let _previous = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }
    struct Metrics(mpsc::UnboundedSender<&'static str>);
    impl spiffe::x509_source::MetricsRecorder for Metrics {
        fn record_update(&self) {
            let _previous = self.0.send("update");
        }
        fn record_reconnect(&self) {
            let _previous = self.0.send("reconnect");
        }
        fn record_error(&self, kind: spiffe::x509_source::MetricsErrorKind) {
            use spiffe::x509_source::MetricsErrorKind::*;
            let _previous = self.0.send(match kind {
                UpdateRejected => "rejected",
                StreamEnded => "ended",
                _ => "error",
            });
        }
    }
    impl spiffe::jwt_source::MetricsRecorder for Metrics {
        fn record_update(&self) {
            let _previous = self.0.send("update");
        }
        fn record_reconnect(&self) {
            let _previous = self.0.send("reconnect");
        }
        fn record_error(&self, _kind: spiffe::jwt_source::MetricsErrorKind) {
            let _previous = self.0.send("error");
        }
    }
    async fn metric(rx: &mut mpsc::UnboundedReceiver<&'static str>, wanted: &str) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while rx.recv().await.unwrap() != wanted {}
        })
        .await
        .expect("source processing barrier");
    }
    async fn serve<Q, R>(
        initial: R,
        header_error: bool,
    ) -> (
        String,
        watch::Sender<Result<R, tonic::Status>>,
        tokio::task::JoinHandle<()>,
    )
    where
        Q: prost::Message + Default + Send + 'static,
        R: prost::Message + Default + Clone + Send + Sync + 'static,
    {
        let (tx, rx) = watch::channel(Ok::<R, tonic::Status>(initial));
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let error_delivered = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let svc = tower::service_fn(
            move |req: tonic::codegen::http::Request<tonic::body::Body>| {
                let rx = rx.clone();
                let calls = Arc::clone(&calls);
                let error_delivered = Arc::clone(&error_delivered);
                async move {
                    let handler = tower::service_fn(move |_: tonic::Request<Q>| {
                        let mut rx = rx.clone();
                        let error_delivered = Arc::clone(&error_delivered);
                        let call = calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        async move {
                            if header_error && call == 1 {
                                while rx.borrow().is_ok() {
                                    rx.changed().await.map_err(|_closed| {
                                        tonic::Status::cancelled("test server closed")
                                    })?;
                                }
                            }
                            // After delivering a denial, stall subsequent reconnects until
                            // the test publishes another item. This gives each processing
                            // acknowledgment exactly one attributable error.
                            if error_delivered.load(std::sync::atomic::Ordering::Acquire)
                                && rx.borrow().is_err()
                            {
                                rx.changed().await.map_err(|_closed| {
                                    tonic::Status::cancelled("test server closed")
                                })?;
                            }
                            let first = rx.borrow_and_update().clone();
                            if header_error {
                                if let Err(e) = &first {
                                    error_delivered
                                        .store(true, std::sync::atomic::Ordering::Release);
                                    return Err(e.clone());
                                }
                            }
                            let updates = futures::stream::unfold(
                                (rx, Some(first), error_delivered),
                                async |(mut rx, first, error_delivered)| {
                                    let item = if let Some(first) = first {
                                        first
                                    } else {
                                        rx.changed().await.ok()?;
                                        let next = rx.borrow_and_update().clone();
                                        next
                                    };
                                    if item.is_err() {
                                        error_delivered
                                            .store(true, std::sync::atomic::Ordering::Release);
                                    }
                                    Some((item, (rx, None, error_delivered)))
                                },
                            );
                            let updates: std::pin::Pin<
                                Box<dyn Stream<Item = Result<R, tonic::Status>> + Send>,
                            > = Box::pin(updates);
                            Ok::<_, tonic::Status>(tonic::Response::new(updates))
                        }
                    });
                    let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                    Ok::<_, std::convert::Infallible>(grpc.server_streaming(handler, req).await)
                }
            },
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .serve_with_incoming(svc, tonic::transport::server::TcpIncoming::from(listener))
                .await
                .unwrap();
        });
        (format!("tcp://{addr}"), tx, task)
    }
    fn response(
        leaf: &[u8],
        key: &[u8],
        bundle: &[u8],
        hint: &str,
        foreign: bool,
    ) -> X509svidResponse {
        let identity = spiffe::X509Svid::parse_from_der(leaf, key).map_or_else(
            |_| "spiffe://example.org/service".into(),
            |s| s.spiffe_id().to_string(),
        );
        let mut r = X509svidResponse {
            svids: vec![X509svid {
                spiffe_id: identity,
                x509_svid: leaf.to_vec().into(),
                x509_svid_key: key.to_vec().into(),
                bundle: bundle.to_vec().into(),
                hint: hint.into(),
            }],
            ..Default::default()
        };
        if foreign {
            r.federated_bundles
                .insert("spiffe://foreign.example".into(), CB.to_vec().into());
        }
        r
    }
    async fn source(
        initial: X509svidResponse,
        picker: bool,
    ) -> (
        spiffe::X509Source,
        watch::Sender<Result<X509svidResponse, tonic::Status>>,
        mpsc::UnboundedReceiver<&'static str>,
        tokio::task::JoinHandle<()>,
    ) {
        source_mode(initial, picker, false).await
    }
    async fn source_mode(
        initial: X509svidResponse,
        picker: bool,
        headers: bool,
    ) -> (
        spiffe::X509Source,
        watch::Sender<Result<X509svidResponse, tonic::Status>>,
        mpsc::UnboundedReceiver<&'static str>,
        tokio::task::JoinHandle<()>,
    ) {
        let (endpoint, tx, server) = serve::<X509svidRequest, _>(initial, headers).await;
        let (mtx, mrx) = mpsc::unbounded_channel();
        let mut builder = spiffe::X509Source::builder()
            .endpoint(endpoint)
            .metrics(Arc::new(Metrics(mtx)))
            .reconnect_backoff(Duration::from_millis(10), Duration::from_millis(10));
        if picker {
            builder = builder.picker(Picker);
        }
        (builder.build().await.unwrap(), tx, mrx, server)
    }
    #[derive(Debug)]
    struct Picker;
    impl spiffe::x509_source::SvidPicker for Picker {
        fn pick_svid(&self, svids: &[Arc<spiffe::X509Svid>]) -> Option<usize> {
            svids.iter().position(|s| s.hint() == Some("wanted"))
        }
    }
    fn cert(der: &[u8]) -> CertificateDer<'static> {
        CertificateDer::from(der.to_vec())
    }
    fn key(der: &[u8]) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der.to_vec()))
    }
    fn roots() -> rustls::RootCertStore {
        let mut r = rustls::RootCertStore::empty();
        r.add(cert(CA)).unwrap();
        r.add(cert(CB)).unwrap();
        r
    }
    fn peer_client(leaf: &[u8], k: &[u8]) -> Arc<rustls::ClientConfig> {
        peer_client_version(leaf, k, &rustls::version::TLS13)
    }
    fn peer_client_version(
        leaf: &[u8],
        k: &[u8],
        version: &'static rustls::SupportedProtocolVersion,
    ) -> Arc<rustls::ClientConfig> {
        Arc::new(
            rustls::ClientConfig::builder_with_protocol_versions(&[version])
                .with_root_certificates(roots())
                .with_client_auth_cert(vec![cert(leaf)], key(k))
                .unwrap(),
        )
    }
    fn peer_server(leaf: &[u8], k: &[u8]) -> Arc<rustls::ServerConfig> {
        peer_server_version(leaf, k, &rustls::version::TLS13)
    }
    fn peer_server_version(
        leaf: &[u8],
        k: &[u8],
        version: &'static rustls::SupportedProtocolVersion,
    ) -> Arc<rustls::ServerConfig> {
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots()))
            .build()
            .unwrap();
        Arc::new(
            rustls::ServerConfig::builder_with_protocol_versions(&[version])
                .with_client_cert_verifier(verifier)
                .with_single_cert(vec![cert(leaf)], key(k))
                .unwrap(),
        )
    }
    #[expect(
        clippy::unwrap_in_result,
        clippy::panic_in_result_fn,
        reason = "in-memory test I/O and fixed fixture name are infallible; protocol failures are returned"
    )]
    fn handshake(
        client: Arc<rustls::ClientConfig>,
        server: Arc<rustls::ServerConfig>,
    ) -> Result<(rustls::ClientConnection, rustls::ServerConnection), rustls::Error> {
        let mut c =
            rustls::ClientConnection::new(client, ServerName::try_from("example.org").unwrap())?;
        let mut s = rustls::ServerConnection::new(server)?;
        for _ in 0..32 {
            let mut bytes = Vec::new();
            c.write_tls(&mut bytes).unwrap();
            if !bytes.is_empty() {
                s.read_tls(&mut Cursor::new(bytes)).unwrap();
                s.process_new_packets()?;
            }
            let mut bytes = Vec::new();
            s.write_tls(&mut bytes).unwrap();
            if !bytes.is_empty() {
                c.read_tls(&mut Cursor::new(bytes)).unwrap();
                c.process_new_packets()?;
            }
            if !c.is_handshaking() && !s.is_handshaking() {
                return Ok((c, s));
            }
        }
        panic!("TLS handshake made no progress");
    }
    struct Configs {
        client: Arc<rustls::ClientConfig>,
        server: Arc<rustls::ServerConfig>,
        client_status: spiffe_rustls::TlsStatus,
        server_status: spiffe_rustls::TlsStatus,
    }
    impl Configs {
        fn new(source: &spiffe::X509Source, policy: spiffe_rustls::TerminalSourcePolicy) -> Self {
            ensure_provider();
            let (client, client_status) = spiffe_rustls::mtls_client(source.clone())
                .terminal_source_policy(policy)
                .build_with_status()
                .unwrap();
            let (server, server_status) = spiffe_rustls::mtls_server(source.clone())
                .terminal_source_policy(policy)
                .build_with_status()
                .unwrap();
            Self {
                client: Arc::new(client),
                server: Arc::new(server),
                client_status,
                server_status,
            }
        }
        fn accept(&self, leaf: &[u8], key: &[u8]) {
            both_accept(&self.client, &self.server, leaf, key);
        }
        fn reject(&self, leaf: &[u8], key: &[u8]) {
            both_reject(&self.client, &self.server, leaf, key);
        }
        async fn applied(&mut self, revision: u64) {
            for status in [&mut self.client_status, &mut self.server_status] {
                tokio::time::timeout(Duration::from_secs(5), async {
                    while status.current().applied_revision < revision {
                        status.changed().await.unwrap();
                    }
                })
                .await
                .expect("TLS revision acknowledgment");
                assert_eq!(status.current().applied_revision, revision);
            }
        }
        async fn terminated(&mut self) {
            for status in [&mut self.client_status, &mut self.server_status] {
                tokio::time::timeout(Duration::from_secs(5), async {
                    while status.current().refreshing {
                        status.changed().await.unwrap();
                    }
                })
                .await
                .expect("TLS termination acknowledgment");
            }
        }
    }

    fn both_accept(
        c: &Arc<rustls::ClientConfig>,
        s: &Arc<rustls::ServerConfig>,
        leaf: &[u8],
        k: &[u8],
    ) {
        for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
            let (client, _) = handshake(Arc::clone(c), peer_server_version(leaf, k, version))
                .expect("outbound peer rejected");
            assert_eq!(client.protocol_version(), Some(version.version));
            let (client, _) = handshake(peer_client_version(leaf, k, version), Arc::clone(s))
                .expect("inbound peer rejected");
            assert_eq!(client.protocol_version(), Some(version.version));
        }
    }

    fn both_reject(
        c: &Arc<rustls::ClientConfig>,
        s: &Arc<rustls::ServerConfig>,
        leaf: &[u8],
        k: &[u8],
    ) {
        for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
            handshake(Arc::clone(c), peer_server_version(leaf, k, version))
                .expect_err("outbound peer accepted");
            handshake(peer_client_version(leaf, k, version), Arc::clone(s))
                .expect_err("inbound peer accepted");
        }
    }

    #[tokio::test]
    async fn denial_at_headers_trailers_and_reconnect_with_identical_recovery() {
        ensure_provider();
        for headers in [true, false] {
            for msg in ["withdrawn", "no identity issued"] {
                let initial = response(A, KA, CA, "", false);
                let (source, tx, mut metrics, server) =
                    source_mode(initial.clone(), false, headers).await;
                let mut configs =
                    Configs::new(&source, spiffe_rustls::TerminalSourcePolicy::RetainFinal);
                configs.accept(A, KA);
                let mut updates = source.updated();
                let _previous = tx.send_replace(Err(tonic::Status::permission_denied(msg)));
                assert_eq!(updates.changed().await.unwrap(), 1);
                assert!(matches!(
                    source.svid(),
                    Err(spiffe::x509_source::X509SourceError::Withdrawn(_))
                ));
                source.bundle_set().unwrap_err();
                assert!(!source.is_healthy());
                configs.reject(A, KA); // immediately after source publication
                configs.applied(1).await;
                configs.reject(A, KA);
                metric(&mut metrics, "reconnect").await;
                let _previous = tx.send_replace(Ok(initial));
                assert_eq!(updates.changed().await.unwrap(), 2);
                configs.applied(2).await;
                configs.accept(A, KA);
                source.shutdown().await;
                server.abort();
            }
        }
    }

    struct PanickingMetrics;
    impl spiffe::x509_source::MetricsRecorder for PanickingMetrics {
        fn record_update(&self) {}
        fn record_reconnect(&self) {}
        fn record_error(&self, kind: spiffe::x509_source::MetricsErrorKind) {
            use spiffe::x509_source::MetricsErrorKind::{StreamConnect, StreamError};
            if matches!(kind, StreamConnect | StreamError) {
                panic!("test callback panic after RPC denial");
            }
        }
    }

    #[tokio::test]
    async fn denial_is_published_before_external_error_callbacks() {
        ensure_provider();
        for headers in [true, false] {
            let (endpoint, tx, server) =
                serve::<X509svidRequest, _>(response(A, KA, CA, "", false), headers).await;
            let source = spiffe::X509Source::builder()
                .endpoint(endpoint)
                .metrics(Arc::new(PanickingMetrics))
                .build()
                .await
                .unwrap();
            let configs = Configs::new(&source, spiffe_rustls::TerminalSourcePolicy::RetainFinal);
            let mut updates = source.updated();
            let _previous = tx.send_replace(Err(tonic::Status::permission_denied("withdrawn")));
            let _observed = tokio::time::timeout(Duration::from_secs(5), updates.changed())
                .await
                .unwrap();
            assert!(
                source.state().withdrawal().is_some(),
                "denial must publish even if diagnostic callbacks panic"
            );
            configs.reject(A, KA);
            source.shutdown().await;
            server.abort();
        }
    }

    #[tokio::test]
    async fn denial_followed_by_malformed_or_unavailable_cannot_reauthorize_tls() {
        ensure_provider();
        for next in [
            Err(tonic::Status::unavailable("temporary")),
            Ok(response(B, &[0], CB, "", false)),
        ] {
            let initial = response(A, KA, CA, "", false);
            let (source, tx, mut metrics, server) = source(initial.clone(), false).await;
            let mut configs =
                Configs::new(&source, spiffe_rustls::TerminalSourcePolicy::RetainFinal);
            configs.accept(A, KA);
            let mut updates = source.updated();
            let _previous = tx.send_replace(Err(tonic::Status::permission_denied("withdrawn")));
            assert_eq!(updates.changed().await.unwrap(), 1);
            metric(&mut metrics, "reconnect").await; // denial error has been recorded
            let _previous = tx.send_replace(next);
            metric(&mut metrics, "error").await; // the next response has been processed
            assert_eq!(source.state().revision(), 1);
            assert!(source.state().withdrawal().is_some());
            configs.reject(A, KA);
            let _previous = tx.send_replace(Ok(initial));
            assert_eq!(updates.changed().await.unwrap(), 2);
            configs.applied(2).await;
            configs.accept(A, KA);
            source.shutdown().await;
            server.abort();
        }
    }

    #[tokio::test]
    async fn missing_required_fields_cannot_reauthorize_withdrawn_tls() {
        ensure_provider();
        let initial = response(A, KA, CA, "", false);
        for field in ["spiffe_id", "svids", "bundle", "key", "certificate"] {
            let mut malformed = initial.clone();
            match field {
                "spiffe_id" => malformed.svids.first_mut().unwrap().spiffe_id.clear(),
                "svids" => malformed.svids.clear(),
                "bundle" => {
                    malformed.svids.first_mut().unwrap().bundle = prost::bytes::Bytes::new();
                }
                "key" => {
                    malformed.svids.first_mut().unwrap().x509_svid_key = prost::bytes::Bytes::new();
                }
                _ => malformed.svids.first_mut().unwrap().x509_svid = prost::bytes::Bytes::new(),
            }
            let (source, tx, mut metrics, server) = source(initial.clone(), false).await;
            let mut configs =
                Configs::new(&source, spiffe_rustls::TerminalSourcePolicy::RetainFinal);
            let mut updates = source.updated();
            configs.accept(A, KA);
            let _previous = tx.send_replace(Err(tonic::Status::permission_denied("withdrawn")));
            assert_eq!(updates.changed().await.unwrap(), 1);
            metric(&mut metrics, "reconnect").await;
            let _previous = tx.send_replace(Ok(malformed));
            metric(&mut metrics, "error").await;
            assert_eq!(source.state().revision(), 1, "missing {field}");
            assert!(source.state().withdrawal().is_some());
            configs.reject(A, KA);
            let _previous = tx.send_replace(Ok(initial.clone()));
            assert_eq!(updates.changed().await.unwrap(), 2);
            configs.applied(2).await;
            configs.accept(A, KA);
            source.shutdown().await;
            server.abort();
        }
    }

    #[tokio::test]
    async fn missing_later_metadata_rejects_trust_replacement_atomically() {
        ensure_provider();
        let initial = response(A, KA, CA, "", false);
        let replacement = response(B, KB, CB, "", false);
        let mut malformed = replacement.clone();
        let mut second = initial.svids.first().unwrap().clone();
        second.spiffe_id.clear();
        malformed.svids.push(second);
        let (source, tx, mut metrics, server) = source(initial, false).await;
        let mut configs = Configs::new(&source, spiffe_rustls::TerminalSourcePolicy::RetainFinal);
        let mut updates = source.updated();
        configs.accept(A, KA);
        let _previous = tx.send_replace(Ok(malformed));
        metric(&mut metrics, "error").await;
        assert_eq!(source.state().revision(), 0);
        configs.accept(A, KA);
        configs.reject(B, KB);
        let _previous = tx.send_replace(Ok(replacement));
        assert_eq!(updates.changed().await.unwrap(), 1);
        configs.applied(1).await;
        configs.reject(A, KA);
        configs.accept(B, KB);
        source.shutdown().await;
        server.abort();
    }

    #[tokio::test]
    async fn transient_and_malformed_updates_retain_authorized_material() {
        ensure_provider();
        // Use independent sources so no earlier transport error can satisfy a later
        // malformed-update processing barrier.
        for update in [
            Err(tonic::Status::unavailable("temporary")),
            Ok(response(B, &[0], CB, "", false)),
        ] {
            let (source, tx, mut metrics, server) =
                source(response(A, KA, CA, "", false), false).await;
            let configs = Configs::new(&source, spiffe_rustls::TerminalSourcePolicy::RetainFinal);
            configs.accept(A, KA);
            let _previous = tx.send_replace(update);
            metric(&mut metrics, "error").await;
            assert_eq!(source.state().revision(), 0);
            configs.accept(A, KA);
            source.shutdown().await;
            server.abort();
        }
        let (source, tx, _metrics, server) = source(response(A, KA, CA, "", false), false).await;
        let mut configs = Configs::new(&source, spiffe_rustls::TerminalSourcePolicy::RetainFinal);
        let mut updates = source.updated();
        let _previous = tx.send_replace(Ok(response(B, KB, CB, "", false)));
        assert_eq!(updates.changed().await.unwrap(), 1);
        configs.applied(1).await;
        configs.reject(A, KA);
        configs.accept(B, KB);
        source.shutdown().await;
        server.abort();
    }

    #[tokio::test]
    async fn temporary_eof_retains_accepted_permission() {
        ensure_provider();
        let (source, tx, mut metrics, server) = source(response(A, KA, CA, "", false), false).await;
        let configs = Configs::new(&source, spiffe_rustls::TerminalSourcePolicy::RetainFinal);
        configs.accept(A, KA);
        drop(tx); // server stream closes, supervisor reconnects
        metric(&mut metrics, "ended").await;
        assert_eq!(source.state().revision(), 0);
        assert!(!source.state().is_closed());
        configs.accept(A, KA);
        source.shutdown().await;
        server.abort();
    }

    #[tokio::test]
    async fn picker_mismatch_and_identity_disappearance_publish_federation_removal() {
        ensure_provider();
        for leaf in [A, OTHER] {
            let (source, tx, _metrics, server) =
                source(response(A, KA, CA, "wanted", true), true).await;
            let mut configs =
                Configs::new(&source, spiffe_rustls::TerminalSourcePolicy::RetainFinal);
            configs.accept(FOREIGN, KB);
            let mut updates = source.updated();
            let _previous = tx.send_replace(Ok(response(
                leaf,
                if leaf == A { KA } else { KB },
                CB,
                "other",
                false,
            )));
            assert_eq!(updates.changed().await.unwrap(), 1);
            assert!(matches!(
                source.svid(),
                Err(spiffe::x509_source::X509SourceError::NoSuitableSvid)
            ));
            assert!(source
                .bundle_set()
                .unwrap()
                .get(&spiffe::TrustDomain::new("foreign.example").unwrap())
                .is_none());
            configs.reject(FOREIGN, KB);
            configs.applied(1).await;
            configs.reject(FOREIGN, KB);
            let _previous = tx.send_replace(Ok(response(B, KB, CB, "wanted", false)));
            assert_eq!(updates.changed().await.unwrap(), 2);
            configs.applied(2).await;
            configs.reject(FOREIGN, KB);
            configs.accept(B, KB);
            source.shutdown().await;
            server.abort();
        }
    }

    #[tokio::test]
    async fn expired_identity_does_not_retain_removed_roots() {
        ensure_provider();
        let (source, tx, _metrics, server) = source(response(A, KA, CA, "", false), false).await;
        let mut configs = Configs::new(&source, spiffe_rustls::TerminalSourcePolicy::RetainFinal);
        configs.accept(A, KA);
        let mut updates = source.updated();
        let _previous = tx.send_replace(Ok(response(EXPIRED, EXPIRED_KEY, CB, "", false)));
        updates.changed().await.unwrap();
        source.svid().unwrap_err();
        assert_eq!(
            source
                .bundle_set()
                .unwrap()
                .get(&spiffe::TrustDomain::new("example.org").unwrap())
                .unwrap()
                .authorities()
                .first()
                .unwrap()
                .as_bytes(),
            CB
        );
        configs.applied(1).await;
        configs.reject(A, KA);
        source.shutdown().await;
        server.abort();
    }

    #[tokio::test]
    async fn accepted_ca_rotation_with_key_conversion_failure_blocks_both_roles() {
        ensure_provider();
        for failing_key in [KB, UNSUPPORTED] {
            spiffe::X509Svid::parse_from_der(A, failing_key).unwrap();
            let err = rustls::sign::CertifiedKey::from_der(
                vec![cert(A)],
                key(failing_key),
                rustls::crypto::CryptoProvider::get_default().unwrap(),
            )
            .unwrap_err();
            if failing_key == KB {
                assert!(matches!(
                    err,
                    rustls::Error::InconsistentKeys(rustls::InconsistentKeys::KeyMismatch)
                ));
            } else {
                assert!(!matches!(err, rustls::Error::InconsistentKeys(_)));
            }
            let (source, tx, _metrics, server) =
                source(response(A, KA, CA, "", false), false).await;
            let mut configs =
                Configs::new(&source, spiffe_rustls::TerminalSourcePolicy::RetainFinal);
            configs.accept(A, KA);
            let mut updates = source.updated();
            let _previous = tx.send_replace(Ok(response(A, failing_key, CB, "", false)));
            updates.changed().await.unwrap();
            configs.reject(A, KA);
            configs.applied(1).await;
            assert!(!configs.client_status.current().available);
            assert!(configs
                .client_status
                .current()
                .error
                .unwrap()
                .to_string()
                .contains("certified key"));
            configs.reject(A, KA);
            let _previous = tx.send_replace(Ok(response(B, KB, CB, "", false)));
            updates.changed().await.unwrap();
            configs.applied(2).await;
            configs.reject(A, KA);
            configs.accept(B, KB);
            source.shutdown().await;
            server.abort();
        }
    }

    fn exchange(client: &mut rustls::ClientConnection, server: &mut rustls::ServerConnection) {
        client.writer().write_all(b"still connected").unwrap();
        let mut bytes = Vec::new();
        client.write_tls(&mut bytes).unwrap();
        server.read_tls(&mut Cursor::new(bytes)).unwrap();
        server.process_new_packets().unwrap();
        let mut payload = [0; 15];
        server.reader().read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"still connected");
    }

    #[tokio::test]
    async fn terminal_policies_and_existing_connections() {
        ensure_provider();
        for policy in [
            spiffe_rustls::TerminalSourcePolicy::RetainFinal,
            spiffe_rustls::TerminalSourcePolicy::FailClosed,
        ] {
            let (source, _tx, _metrics, server) =
                source(response(A, KA, CA, "", false), false).await;
            let mut configs = Configs::new(&source, policy);
            configs.accept(A, KA);
            let (mut outbound, mut peer_server) =
                handshake(Arc::clone(&configs.client), peer_server(A, KA)).unwrap();
            let (mut peer_client, mut inbound) =
                handshake(peer_client(A, KA), Arc::clone(&configs.server)).unwrap();
            source.shutdown().await;
            configs.terminated().await;
            assert!(source.state().is_closed());
            if policy == spiffe_rustls::TerminalSourcePolicy::RetainFinal {
                configs.accept(A, KA);
            } else {
                configs.reject(A, KA);
            }
            exchange(&mut outbound, &mut peer_server);
            exchange(&mut peer_client, &mut inbound);
            server.abort();
        }
    }

    #[tokio::test]
    async fn runtime_teardown_closes_unpolled_source_and_tls_watchers() {
        ensure_provider();
        let (endpoint, _tx, server) =
            serve::<X509svidRequest, _>(response(A, KA, CA, "", false), false).await;
        let (source, retain, closed) = tokio::task::spawn_blocking(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let material = runtime.block_on(async {
                let source = spiffe::X509Source::builder()
                    .endpoint(endpoint)
                    .build()
                    .await
                    .unwrap();
                let retain =
                    Configs::new(&source, spiffe_rustls::TerminalSourcePolicy::RetainFinal);
                let closed = Configs::new(&source, spiffe_rustls::TerminalSourcePolicy::FailClosed);
                assert!(!source.is_healthy(), "supervisor has not been polled");
                (source, retain, closed) // no yield after spawning any watcher
            });
            drop(runtime);
            material
        })
        .await
        .unwrap();
        assert!(source.state().is_closed());
        source.svid().unwrap_err();
        assert!(!retain.client_status.current().refreshing);
        assert!(!closed.server_status.current().refreshing);
        retain.accept(A, KA);
        closed.reject(A, KA);
        server.abort();
    }

    #[tokio::test]
    async fn retain_final_never_resurrects_withdrawal_or_failed_conversion() {
        ensure_provider();
        for deny in [true, false] {
            let (source, tx, _metrics, server) =
                source(response(A, KA, CA, "", false), false).await;
            let mut configs =
                Configs::new(&source, spiffe_rustls::TerminalSourcePolicy::RetainFinal);
            configs.accept(A, KA);
            let mut updates = source.updated();
            let _previous = tx.send_replace(if deny {
                Err(tonic::Status::permission_denied("withdrawn"))
            } else {
                Ok(response(A, KB, CB, "", false))
            });
            updates.changed().await.unwrap();
            source.shutdown().await;
            configs.terminated().await;
            configs.reject(A, KA);
            server.abort();
        }
    }

    #[tokio::test]
    async fn interrupted_concurrent_shutdown_preserves_final_tls_revision() {
        use std::future::Future as _;
        use std::task::Poll;

        for policy in [
            spiffe_rustls::TerminalSourcePolicy::RetainFinal,
            spiffe_rustls::TerminalSourcePolicy::FailClosed,
        ] {
            // Denial, failed conversion, recovery from that block, and transient outage.
            for event in 0..4 {
                let (source, tx, mut metrics, server) =
                    source(response(A, KA, CA, "", false), false).await;
                let mut configs = Configs::new(&source, policy);
                configs.accept(A, KA); // otherwise valid peers in both roles and TLS versions
                let mut updates = source.updated();
                let _previous = tx.send_replace(match event {
                    0 => Err(tonic::Status::permission_denied("withdrawn")),
                    3 => Err(tonic::Status::unavailable("temporary")),
                    _ => Ok(response(A, KB, CB, "", false)),
                });
                let revision = if event == 3 {
                    metric(&mut metrics, "reconnect").await;
                    configs.accept(A, KA); // outage retains current permission
                    0
                } else {
                    updates.changed().await.unwrap();
                    configs.reject(A, KA);
                    if event == 2 {
                        let _previous = tx.send_replace(Ok(response(B, KB, CB, "", false)));
                        updates.changed().await.unwrap();
                        2
                    } else {
                        1
                    }
                };

                // Poll both callers without scheduling the supervisor in between.
                // Discard the first join waiter, then drive the retained join from the second.
                let mut first = Box::pin(source.shutdown());
                assert!(
                    std::future::poll_fn(|cx| Poll::Ready(first.as_mut().poll(cx)))
                        .await
                        .is_pending()
                );
                let mut second = Box::pin(source.shutdown_with_timeout(Duration::from_secs(5)));
                assert!(
                    std::future::poll_fn(|cx| Poll::Ready(second.as_mut().poll(cx)))
                        .await
                        .is_pending()
                );
                drop(first);
                second.await.unwrap();
                configs.applied(revision).await;
                assert!(source.state().is_closed());
                assert_eq!(source.state().revision(), revision);

                for status in [&configs.client_status, &configs.server_status] {
                    let final_state = status.current();
                    assert_eq!(final_state.source_revision, revision);
                    assert!(!final_state.refreshing);
                    match event {
                        0 => assert!(matches!(
                            final_state.error.as_deref(),
                            Some(spiffe_rustls::Error::Source(
                                spiffe::x509_source::X509SourceError::Withdrawn(_)
                            ))
                        )),
                        1 if policy == spiffe_rustls::TerminalSourcePolicy::RetainFinal => {
                            assert!(matches!(final_state.error.as_deref(), Some(
                                spiffe_rustls::Error::MaterialUnavailable(cause)
                            ) if matches!(cause.as_ref(), spiffe_rustls::Error::CertifiedKey(_))));
                        }
                        _ if policy == spiffe_rustls::TerminalSourcePolicy::FailClosed => {
                            assert!(matches!(
                                final_state.error.as_deref(),
                                Some(spiffe_rustls::Error::SourceClosed)
                            ));
                        }
                        _ => assert!(final_state.available),
                    }
                }
                if event < 2 || policy == spiffe_rustls::TerminalSourcePolicy::FailClosed {
                    configs.reject(A, KA);
                } else if event == 2 {
                    configs.reject(A, KA);
                    configs.accept(B, KB); // RetainFinal uses recovered B, never old A
                } else {
                    configs.accept(A, KA);
                }
                source.shutdown_configured().await.unwrap();
                server.abort();
            }
        }
    }

    #[tokio::test]
    async fn jwt_withdrawal_survives_interrupted_shutdown() {
        use std::future::Future as _;
        use std::task::Poll;
        let initial = JwtBundlesResponse {
            bundles: HashMap::from([(
                "spiffe://example.org".into(),
                br#"{"keys":[{"kid":"a","kty":"EC","crv":"P-256","x":"unused","y":"unused"}]}"#
                    .to_vec()
                    .into(),
            )]),
        };
        let (endpoint, tx, server) = serve::<JwtBundlesRequest, _>(initial, false).await;
        let source = spiffe::JwtSource::builder()
            .endpoint(endpoint)
            .build()
            .await
            .unwrap();
        source.bundle_set().unwrap();
        let mut updates = source.updated();
        let _previous = tx.send_replace(Err(tonic::Status::permission_denied("withdrawn")));
        assert_eq!(updates.changed().await.unwrap(), 1);
        let mut first = Box::pin(source.shutdown());
        assert!(
            std::future::poll_fn(|cx| Poll::Ready(first.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        drop(first);
        source.shutdown_configured().await.unwrap();
        let final_state = source.state();
        assert!(final_state.is_closed());
        assert_eq!(final_state.revision(), 1);
        assert!(matches!(
            final_state.bundle_set(),
            Err(spiffe::jwt_source::JwtSourceError::Withdrawn(_))
        ));
        source.shutdown().await;
        server.abort();
    }

    #[tokio::test]
    async fn jwt_required_map_rejection_preserves_withdrawal_and_domain_removal() {
        // Public P-256 authority from the signed JWT policy corpus, kept local
        // so this integration target remains self-contained when packaged.
        let jwks = br#"{"keys":[{"crv":"P-256","kid":"probe","kty":"EC","x":"pf-F3qt3WiBQ2hPjVIp0W8C-ltc7VGCJqW-0sJgoKTI","y":"bsqDObxnMnAkXVbmLLlxinbSRyaLNL-28UWmN5rlg44"}]}"#;
        let initial = JwtBundlesResponse {
            bundles: HashMap::from([
                ("spiffe://example.org".into(), jwks.to_vec().into()),
                ("spiffe://foreign.example".into(), jwks.to_vec().into()),
            ]),
        };
        let foreign = spiffe::TrustDomain::new("foreign.example").unwrap();
        let (endpoint, tx, server) = serve::<JwtBundlesRequest, _>(initial.clone(), false).await;
        let (metrics_tx, mut metrics) = mpsc::unbounded_channel();
        let source = spiffe::JwtSource::builder()
            .endpoint(endpoint)
            .metrics(Arc::new(Metrics(metrics_tx)))
            .reconnect_backoff(Duration::ZERO, Duration::ZERO)
            .build()
            .await
            .unwrap();
        let mut updates = source.updated();
        let _previous = tx.send_replace(Ok(JwtBundlesResponse::default()));
        metric(&mut metrics, "error").await;
        assert_eq!(source.state().revision(), 0);
        assert_eq!(source.bundle_set().unwrap().len(), 2);
        let _previous = tx.send_replace(Err(tonic::Status::permission_denied("withdrawn")));
        assert_eq!(updates.changed().await.unwrap(), 1);
        metric(&mut metrics, "reconnect").await;
        let _previous = tx.send_replace(Ok(JwtBundlesResponse::default()));
        metric(&mut metrics, "error").await;
        assert_eq!(source.state().revision(), 1);
        assert!(source.state().withdrawal().is_some());
        let _previous = tx.send_replace(Ok(initial.clone()));
        assert_eq!(updates.changed().await.unwrap(), 2);
        assert_eq!(source.bundle_set().unwrap().len(), 2);
        let mut removed = initial;
        removed.bundles.remove("spiffe://foreign.example");
        let _previous = tx.send_replace(Ok(removed));
        assert_eq!(updates.changed().await.unwrap(), 3);
        assert_eq!(source.bundle_set().unwrap().len(), 1);
        assert!(source.bundle_set().unwrap().get(&foreign).is_none());
        let empty_authorities = JwtBundlesResponse {
            bundles: HashMap::from([(
                "spiffe://example.org".into(),
                br#"{"keys":[]}"#.to_vec().into(),
            )]),
        };
        let _previous = tx.send_replace(Ok(empty_authorities));
        assert_eq!(updates.changed().await.unwrap(), 4);
        assert_eq!(source.bundle_set().unwrap().len(), 1);
        assert!(!source.is_healthy());
        assert!(source.state().withdrawal().is_none());
        source.shutdown().await;
        server.abort();
    }

    #[tokio::test]
    async fn jwt_bundle_denial_is_scoped_and_identical_response_recovers() {
        for headers in [true, false] {
            for msg in ["denied", "no identity issued"] {
                let initial=JwtBundlesResponse { bundles: HashMap::from([("spiffe://example.org".into(),br#"{"keys":[{"kid":"a","kty":"EC","crv":"P-256","x":"unused","y":"unused"}]}"#.to_vec().into())]) };
                let (endpoint, tx, server) =
                    serve::<JwtBundlesRequest, _>(initial.clone(), headers).await;
                let source = spiffe::JwtSource::builder()
                    .endpoint(endpoint)
                    .reconnect_backoff(Duration::from_millis(10), Duration::from_millis(10))
                    .build()
                    .await
                    .unwrap();
                let mut updates = source.updated();
                let _previous = tx.send_replace(Err(tonic::Status::permission_denied(msg)));
                assert_eq!(updates.changed().await.unwrap(), 1);
                assert!(matches!(
                    source.bundle_set(),
                    Err(spiffe::jwt_source::JwtSourceError::Withdrawn(_))
                ));
                assert!(!source.is_healthy());
                let _previous = tx.send_replace(Ok(initial));
                assert_eq!(updates.changed().await.unwrap(), 2);
                assert_eq!(source.bundle_set().unwrap().len(), 1);
                source.shutdown().await;
                server.abort();
            }
        }
    }
    #[tokio::test]
    async fn usable_identity_with_federation_removal_keeps_only_current_domains() {
        ensure_provider();
        for empty_bundle in [false, true] {
            let (source, tx, _metrics, server) = source(response(A, KA, CA, "", true), false).await;
            let mut configs =
                Configs::new(&source, spiffe_rustls::TerminalSourcePolicy::RetainFinal);
            configs.accept(FOREIGN, KB);
            configs.accept(A, KA);
            let mut updates = source.updated();
            let mut replacement = response(A, KA, CA, "", empty_bundle);
            if empty_bundle {
                // Empty optional federation is a valid accepted root replacement.
                replacement
                    .federated_bundles
                    .insert("spiffe://foreign.example".into(), Vec::new().into());
            }
            let _previous = tx.send_replace(Ok(replacement));
            updates.changed().await.unwrap();
            configs.applied(1).await;
            assert!(configs.client_status.current().available);
            configs.reject(FOREIGN, KB);
            configs.accept(A, KA);
            source.shutdown().await;
            server.abort();
        }
    }
}
