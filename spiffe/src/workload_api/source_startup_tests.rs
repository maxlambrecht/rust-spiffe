// Included for each source; exercises public builders and real wire statuses.
use crate::workload_api::lifecycle_test_support::{poll_once, OnDrop};
use crate::workload_api::startup_test_support::{self as support, watchdog, Step};
use crate::{transport::EndpointError, WorkloadApiError};
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::{mpsc, oneshot};

struct Metrics(mpsc::Sender<MetricsErrorKind>);
impl MetricsRecorder for Metrics {
    fn record_update(&self) {}
    fn record_reconnect(&self) {}
    fn record_error(&self, kind: MetricsErrorKind) {
        let _result = self.0.try_send(kind);
    }
}

fn status_cause<'a>(error: &'a (dyn std::error::Error + 'static)) -> &'a tonic::Status {
    if let Some(status) = error.downcast_ref::<tonic::Status>() {
        return status;
    }
    status_cause(
        error
            .source()
            .expect("gRPC status must remain in the cause chain"),
    )
}

#[tokio::test]
async fn unsupported_rpc_headers_and_trailers_fail_once_with_original_status() {
    for trailers in [false, true] {
        let step = if trailers {
            Step::Trailers(tonic::Code::Unimplemented)
        } else {
            Step::Headers(tonic::Code::Unimplemented)
        };
        let mut server = support::server(vec![step]).await;
        let (tx, mut errors) = mpsc::channel(128);
        let result = watchdog(
            Source::builder()
                .endpoint(&server.endpoint)
                .reconnect_backoff(Duration::from_secs(30), Duration::from_secs(30))
                .metrics(Arc::new(Metrics(tx)))
                .build(),
        )
        .await;
        let error = result.unwrap_err();
        assert!(matches!(error, SourceError::UnsupportedRpc(_)));
        assert!(
            error.to_string().contains(RPC),
            "RPC must be diagnosed: {error}"
        );
        let status = status_cause(&error);
        assert_eq!(status.code(), tonic::Code::Unimplemented);
        assert_eq!(status.message(), "required RPC unavailable");
        let original = status;
        assert_eq!(original.details(), b"startup-probe");
        assert_eq!(
            original.metadata().get("failure-stage").unwrap(),
            if trailers { "trailers" } else { "headers" }
        );
        assert_eq!(
            watchdog(server.calls.recv()).await.unwrap(),
            format!("/SpiffeWorkloadAPI/{RPC}")
        );
        assert!(matches!(
            server.calls.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        assert_eq!(
            watchdog(errors.recv()).await.unwrap(),
            if trailers {
                MetricsErrorKind::StreamError
            } else {
                MetricsErrorKind::StreamConnect
            }
        );
        assert_eq!(
            watchdog(errors.recv()).await.unwrap(),
            MetricsErrorKind::InitialSyncFailed
        );
    }
}

#[tokio::test]
async fn unsupported_rpc_during_initial_reconnect_remains_terminal() {
    for step in [
        Step::Headers(tonic::Code::Unimplemented),
        Step::Trailers(tonic::Code::Unimplemented),
    ] {
        let mut server = support::server(vec![Step::Eof, step]).await;
        let error = watchdog(
            Source::builder()
                .endpoint(&server.endpoint)
                .reconnect_backoff(Duration::from_millis(1), Duration::from_millis(1))
                .build(),
        )
        .await
        .unwrap_err();
        assert_eq!(status_cause(&error).code(), tonic::Code::Unimplemented);
        assert!(error.to_string().contains(RPC));
        for _ in 0..2 {
            watchdog(server.calls.recv()).await.unwrap();
        }
        assert!(matches!(
            server.calls.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }
}
#[tokio::test]
async fn recoverable_rpc_statuses_and_no_identity_retry_until_valid() {
    for first in [
        Step::Headers(tonic::Code::Unavailable),
        Step::Trailers(tonic::Code::Unavailable),
        Step::Headers(tonic::Code::DeadlineExceeded),
        Step::Headers(tonic::Code::PermissionDenied),
        Step::NoIdentity,
        Step::Headers(tonic::Code::Unauthenticated),
        Step::Headers(tonic::Code::Internal),
        Step::Headers(tonic::Code::Unknown),
        Step::Headers(tonic::Code::Cancelled),
        Step::Malformed,
    ] {
        let mut server = support::server(vec![first, Step::Valid]).await;
        let source = watchdog(
            Source::builder()
                .endpoint(&server.endpoint)
                .reconnect_backoff(Duration::from_millis(1), Duration::from_millis(1))
                .build(),
        )
        .await
        .unwrap();
        source.bundle_set().unwrap();
        assert!(!source.state().is_closed());
        assert!(source.state().withdrawal().is_none());
        for _ in 0..2 {
            watchdog(server.calls.recv()).await.unwrap();
        }
        watchdog(source.shutdown()).await;
    }
}

#[tokio::test]
async fn invalid_argument_headers_and_trailers_keep_existing_fast_failure() {
    for step in [
        Step::Headers(tonic::Code::InvalidArgument),
        Step::Trailers(tonic::Code::InvalidArgument),
    ] {
        let mut server = support::server(vec![step]).await;
        let error = watchdog(
            Source::builder()
                .endpoint(&server.endpoint)
                .reconnect_backoff(Duration::from_secs(30), Duration::from_secs(30))
                .build(),
        )
        .await
        .unwrap_err();
        assert_eq!(status_cause(&error).code(), tonic::Code::InvalidArgument);
        watchdog(server.calls.recv()).await.unwrap();
        assert!(matches!(
            server.calls.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }
}

#[tokio::test]
async fn invalid_fixed_endpoints_fail_before_retry_or_metrics() {
    for (raw, kind) in [
        ("not a URI", "parse"),
        ("tcp://[::1", "parse"),
        ("tcp://127.0.0.1:99999", "parse"),
        ("invalid://fixed", "scheme"),
        ("http://127.0.0.1:80", "scheme"),
        ("tcp://localhost:80", "host"),
        ("tcp://127.0.0.1", "port"),
        ("unix://host/socket", "authority"),
        ("unix:/", "path"),
        ("tcp://user:dummy@127.0.0.1:80", "userinfo"),
    ] {
        let (tx, mut errors) = mpsc::channel(128);
        let mut build = Box::pin(
            Source::builder()
                .endpoint(raw)
                .metrics(Arc::new(Metrics(tx)))
                .build(),
        );
        let result = poll_once(build.as_mut()).await;
        let std::task::Poll::Ready(Err(SourceError::Source(WorkloadApiError::Endpoint(error)))) =
            result
        else {
            panic!("fixed invalid endpoint must fail on first poll: {raw}, {result:?}");
        };
        match (kind, &error) {
            ("parse", EndpointError::Parse(cause)) => assert_ne!(cause.to_string(), ""),
            ("scheme", EndpointError::InvalidScheme)
            | ("host", EndpointError::TcpHostNotIp)
            | ("port", EndpointError::TcpMissingPort)
            | ("authority", EndpointError::UnixAuthorityNotAllowed)
            | ("path", EndpointError::UnixMissingPath)
            | ("userinfo", EndpointError::HasUserInfo) => {}
            _ => panic!("unexpected endpoint classification: {raw}: {error:?}"),
        }
        assert!(!error.to_string().contains("dummy"));
        assert!(
            errors.try_recv().is_err(),
            "no retry diagnostics or client attempts"
        );
    }
}

#[tokio::test]
async fn custom_factory_identical_endpoint_errors_remain_recoverable_and_last_setter_wins() {
    let server = support::server(vec![Step::Valid]).await;
    let endpoint = server.endpoint.clone();
    let attempts = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&attempts);
    let factory: Factory = Arc::new(move || {
        let n = count.fetch_add(1, Ordering::SeqCst);
        let endpoint = endpoint.clone();
        Box::pin(async move {
            if n < 4 {
                Err(EndpointError::InvalidScheme.into())
            } else {
                crate::WorkloadApiClient::connect_to(endpoint).await
            }
        })
    });
    let source = watchdog(
        Source::builder()
            .endpoint("invalid://overridden")
            .client_factory(factory)
            .reconnect_backoff(Duration::from_millis(1), Duration::from_millis(1))
            .build(),
    )
    .await
    .unwrap();
    assert_eq!(attempts.load(Ordering::SeqCst), 5);
    watchdog(source.shutdown()).await;
    let source = watchdog(
        Source::builder()
            .client_factory(Arc::new(|| Box::pin(std::future::pending())))
            .endpoint(&server.endpoint)
            .build(),
    )
    .await
    .unwrap();
    watchdog(source.shutdown()).await;
}

#[tokio::test(start_paused = true)]
async fn recoverable_initial_timeout_and_construction_cancellation_drop_owned_future() {
    for timeout in [false, true] {
        let (entry, entered) = oneshot::channel();
        let (drop_tx, dropped) = oneshot::channel();
        let slot = std::sync::Mutex::new(Some((entry, OnDrop(Some(drop_tx)))));
        let factory: Factory = Arc::new(move || {
            let (entry, drop) = slot.lock().unwrap().take().unwrap();
            Box::pin(async move {
                let _drop = drop;
                entry.send(()).unwrap();
                std::future::pending().await
            })
        });
        let builder = Source::builder().client_factory(factory);
        let builder = if timeout {
            builder.initial_sync_timeout(Duration::from_secs(5))
        } else {
            builder
        };
        let mut build = Box::pin(builder.build());
        tokio::select! { _ = entered => {}, _ = &mut build => panic!("factory must remain pending") }
        if timeout {
            tokio::time::advance(Duration::from_secs(5)).await;
            assert!(matches!(build.await, Err(SourceError::InitialSyncTimeout)));
        } else {
            drop(build);
        }
        watchdog(dropped).await.unwrap();
    }
}

#[tokio::test(start_paused = true)]
async fn repeated_recoverable_errors_respect_configured_initial_timeout() {
    let attempts = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&attempts);
    let factory: Factory = Arc::new(move || {
        count.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Err(WorkloadApiError::NoIdentityIssued) })
    });
    let result = Source::builder()
        .client_factory(factory)
        .reconnect_backoff(Duration::from_secs(1), Duration::from_secs(1))
        .initial_sync_timeout(Duration::from_secs(5))
        .build()
        .await;
    assert!(matches!(result, Err(SourceError::InitialSyncTimeout)));
    assert!(attempts.load(Ordering::SeqCst) >= 2);
}

#[tokio::test]
async fn unavailable_tcp_endpoint_recovers_without_rebuilding() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let (tx, mut errors) = mpsc::channel(128);
    let build = Source::builder()
        .endpoint(format!("tcp://{addr}"))
        .reconnect_backoff(Duration::from_millis(10), Duration::from_millis(10))
        .metrics(Arc::new(Metrics(tx)))
        .build();
    tokio::pin!(build);
    tokio::select! { kind = errors.recv() => assert_eq!(kind.unwrap(), MetricsErrorKind::ClientCreation), _ = &mut build => panic!("service is absent") }
    let _server = support::serve(
        tokio::net::TcpListener::bind(addr).await.unwrap(),
        vec![Step::Valid],
    );
    let source = watchdog(build).await.unwrap();
    source.bundle_set().unwrap();
    watchdog(source.shutdown()).await;
}

#[tokio::test]
async fn valid_unavailable_endpoint_keeps_initial_timeout() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let (tx, mut errors) = mpsc::channel(128);
    let result = watchdog(
        Source::builder()
            .endpoint(format!("tcp://{addr}"))
            .reconnect_backoff(Duration::from_millis(1), Duration::from_millis(1))
            .initial_sync_timeout(Duration::from_millis(50))
            .metrics(Arc::new(Metrics(tx)))
            .build(),
    )
    .await;
    assert!(matches!(result, Err(SourceError::InitialSyncTimeout)));
    assert_eq!(
        watchdog(errors.recv()).await.unwrap(),
        MetricsErrorKind::ClientCreation
    );
}

#[tokio::test]
async fn steady_state_unimplemented_retries_and_does_not_resurrect_withdrawn_material() {
    for denied in [false, true] {
        for (unsupported, trailers) in [
            (Step::Headers(tonic::Code::Unimplemented), false),
            (Step::Trailers(tonic::Code::Unimplemented), true),
            (Step::ValidThenTrailers(tonic::Code::Unimplemented), true),
        ] {
            if denied && matches!(unsupported, Step::ValidThenTrailers(_)) {
                continue;
            }
            let mut steps = vec![Step::Valid];
            if denied {
                steps.push(Step::Headers(tonic::Code::PermissionDenied));
            }
            steps.extend([unsupported, Step::Valid]);
            let mut server = support::server(steps).await;
            let (tx, mut errors) = mpsc::channel(128);
            let source = watchdog(
                Source::builder()
                    .endpoint(&server.endpoint)
                    .reconnect_backoff(Duration::from_secs(30), Duration::from_secs(30))
                    .metrics(Arc::new(Metrics(tx)))
                    .build(),
            )
            .await
            .unwrap();
            watchdog(server.calls.recv()).await.unwrap(); // constructor RPC
            if denied {
                assert_eq!(
                    watchdog(errors.recv()).await.unwrap(),
                    MetricsErrorKind::StreamConnect
                );
                assert!(matches!(
                    source.bundle_set(),
                    Err(SourceError::Withdrawn(_))
                ));
                assert!(source.state().withdrawal().is_some());
                tokio::time::pause();
                tokio::time::advance(Duration::from_secs(31)).await;
                tokio::time::resume();
            }
            assert_eq!(
                watchdog(errors.recv()).await.unwrap(),
                if trailers {
                    MetricsErrorKind::StreamError
                } else {
                    MetricsErrorKind::StreamConnect
                }
            );
            let state = source.state();
            assert!(!state.is_closed());
            assert_eq!(state.withdrawal().is_some(), denied);
            assert_eq!(source.bundle_set().is_ok(), !denied);
            assert_eq!(state.revision(), u64::from(denied));
            assert_eq!(source.is_healthy(), !denied);
            let mut updates = source.updated();
            tokio::time::pause();
            tokio::time::advance(Duration::from_secs(31)).await;
            tokio::time::resume();
            if denied {
                watchdog(updates.changed()).await.unwrap();
                assert!(source.state().withdrawal().is_none());
                assert_eq!(source.state().revision(), 2);
            } else {
                // A valid replay is accepted without a material revision.
                for _ in 0..2 {
                    watchdog(server.calls.recv()).await.unwrap();
                }
                assert_eq!(source.state().revision(), 0);
            }
            watchdog(source.shutdown()).await;
        }
    }
}

#[tokio::test(start_paused = true)]
async fn invalid_fixed_scheme_returns_cause_instead_of_configured_timeout() {
    let result = Source::builder()
        .endpoint("invalid://fixed")
        .reconnect_backoff(Duration::from_secs(1), Duration::from_secs(1))
        .initial_sync_timeout(Duration::from_secs(5))
        .build()
        .await;
    assert!(
        matches!(
            result,
            Err(SourceError::Source(WorkloadApiError::Endpoint(
                EndpointError::InvalidScheme
            )))
        ),
        "expected the fixed endpoint cause, got {result:?}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn missing_unix_socket_recovers_without_rebuilding() {
    let socket = support::UnixSocket::new();
    let (tx, mut errors) = mpsc::channel(128);
    let build = Source::builder()
        .endpoint(socket.endpoint())
        .reconnect_backoff(Duration::from_millis(10), Duration::from_millis(10))
        .metrics(Arc::new(Metrics(tx)))
        .build();
    tokio::pin!(build);
    tokio::select! { kind = errors.recv() => assert_eq!(kind.unwrap(), MetricsErrorKind::ClientCreation), _ = &mut build => panic!("socket is absent") }
    let _server = support::serve_unix(&socket);
    let source = watchdog(build).await.unwrap();
    source.bundle_set().unwrap();
    watchdog(source.shutdown()).await;
}

#[tokio::test]
async fn unsuccessful_http2_handshake_remains_recoverable() {
    use tokio::io::AsyncWriteExt as _;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let build = Source::builder()
        .endpoint(format!("tcp://{addr}"))
        .reconnect_backoff(Duration::from_millis(10), Duration::from_millis(10))
        .build();
    tokio::pin!(build);
    let (mut peer, _) = tokio::select! {
        accepted = listener.accept() => accepted.unwrap(),
        _ = &mut build => panic!("HTTP/2 handshake is pending"),
    };
    // An HTTP/1 response aborts this attempt. Tonic can open the replacement
    // connection before that failure is reported, so keep accepting before
    // waiting for startup.
    peer.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n")
        .await
        .unwrap();
    drop(peer);
    assert!(
        poll_once(build.as_mut()).await.is_pending(),
        "handshake interruption must remain retryable"
    );
    let _server = support::serve(listener, vec![Step::Valid]);
    let source = watchdog(build).await.unwrap();
    source.bundle_set().unwrap();
    watchdog(source.shutdown()).await;
}

#[tokio::test]
async fn custom_factory_unimplemented_is_not_misattributed_to_required_rpc() {
    let server = support::server(vec![Step::Valid]).await;
    let endpoint = server.endpoint.clone();
    let attempts = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&attempts);
    let factory: Factory = Arc::new(move || {
        let n = count.fetch_add(1, Ordering::SeqCst);
        let endpoint = endpoint.clone();
        Box::pin(async move {
            if n < 2 {
                Err(WorkloadApiError::from_status(tonic::Status::unimplemented(
                    "custom setup operation",
                )))
            } else {
                crate::WorkloadApiClient::connect_to(endpoint).await
            }
        })
    });
    let source = watchdog(
        Source::builder()
            .client_factory(factory)
            .reconnect_backoff(Duration::from_millis(1), Duration::from_millis(1))
            .build(),
    )
    .await
    .unwrap();
    assert_eq!(attempts.load(Ordering::SeqCst), 3);
    watchdog(source.shutdown()).await;
}
