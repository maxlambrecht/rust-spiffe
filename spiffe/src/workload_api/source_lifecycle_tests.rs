// Included by both source modules so every lifecycle contract runs independently.

async fn joined_shutdown(source: &Source, task: &tokio::task::AbortHandle) {
    tokio::time::timeout(Duration::from_secs(2), source.shutdown())
        .await
        .expect("graceful shutdown must abandon pending setup");
    assert!(
        task.is_finished(),
        "shutdown return must observe actual termination"
    );
}

#[tokio::test]
async fn pending_factory_is_dropped_and_joined_without_release() {
    let server = server(false);
    let Gate {
        factory,
        entered,
        release,
        dropped,
    } = gated(Arc::clone(&server.factory), false);
    let source = build(factory, None).await;
    entered.await.unwrap();
    let task = observer(&source);
    joined_shutdown(&source, &task).await;
    dropped.await.unwrap();
    assert!(
        release.send(()).is_err(),
        "factory receiver must already be destroyed"
    );
    assert_eq!(source.state().revision(), 0);
    assert!(
        source.state().withdrawal().is_none(),
        "cancellation is not withdrawal"
    );
}

#[tokio::test]
async fn pending_connector_and_http2_preface_are_dropped_and_joined() {
    for handshake in [false, true] {
        let server = server(false);
        let Gate {
            factory,
            entered,
            release,
            dropped,
        } = transport_gate(Arc::clone(&server.factory), handshake);
        let source = build(factory, None).await;
        entered.await.unwrap();
        let task = observer(&source);
        joined_shutdown(&source, &task).await;
        dropped.await.unwrap();
        drop(release);
    }
}

#[tokio::test]
async fn pending_rpc_headers_and_quiet_stream_cancel() {
    for stall_headers in [true, false] {
        let server = server(stall_headers);
        let source = build(Arc::clone(&server.factory), None).await;
        let task = observer(&source);
        if stall_headers {
            server.headers_entered.notified().await;
        } else {
            server.read_entered.notified().await;
        }
        joined_shutdown(&source, &task).await;
        assert_eq!(server.calls.load(Ordering::SeqCst), 2);
    }
}

#[tokio::test]
async fn last_public_drop_releases_task_but_remaining_clone_prevents_cleanup() {
    let server = server(false);
    let Gate {
        factory,
        entered,
        release,
        mut dropped,
    } = gated(Arc::clone(&server.factory), false);
    let source = build(factory, None).await;
    entered.await.unwrap();
    let task = observer(&source);
    let token = source.inner.cancel.clone();
    let weak = Arc::downgrade(&source.inner);
    let remaining = source.clone();
    drop(source);
    assert!(!token.is_cancelled());
    assert!(!task.is_finished());
    assert!(matches!(
        dropped.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    drop(remaining);
    assert!(token.is_cancelled());
    finished(&task).await;
    dropped.await.unwrap();
    assert_eq!(
        weak.strong_count(),
        0,
        "join owner must not keep Inner alive after destruction"
    );
    assert!(release.send(()).is_err());
}

#[tokio::test]
async fn cancelled_and_dormant_shutdown_waiters_retain_join_ownership() {
    for entry in 0..4 {
        let (source, release, destroyed) = controlled(if entry == 3 {
            None
        } else {
            Some(Duration::from_secs(60))
        });
        let task = observer(&source);
        let mut first = Box::pin(async {
            match entry {
                0 => source.shutdown().await,
                1 => source
                    .shutdown_with_timeout(Duration::from_secs(60))
                    .await
                    .unwrap(),
                _ => source.shutdown_configured().await.unwrap(),
            }
        });
        assert!(poll_once(first.as_mut()).await.is_pending());
        assert!(source.inner.cancel.is_cancelled());
        let mut second = Box::pin(source.shutdown_configured());
        assert!(
            poll_once(second.as_mut()).await.is_pending(),
            "concurrent request is not completion"
        );
        drop(first);
        drop(second);
        let mut retry = Box::pin(source.shutdown());
        assert!(
            poll_once(retry.as_mut()).await.is_pending(),
            "discarding every temporary waiter must retain the join"
        );
        // A dormant waiter must not own a coordination lock. Another caller
        // observes completion without polling or dropping that dormant waiter.
        release.send(()).unwrap();
        finished(&task).await;
        source.shutdown_configured().await.unwrap();
        assert!(task.is_finished());
        retry.await;
        destroyed.await.unwrap();
        source.shutdown_with_timeout(Duration::ZERO).await.unwrap();
    }
}

#[tokio::test(start_paused = true)]
async fn interrupted_timeout_abort_is_not_completion() {
    let (source, release, destroyed) = controlled(None);
    let task = observer(&source);
    let mut timed = Box::pin(source.shutdown_with_timeout(Duration::from_secs(10)));
    let mut longer = Box::pin(source.shutdown_with_timeout(Duration::from_secs(30)));
    assert!(poll_once(timed.as_mut()).await.is_pending());
    assert!(poll_once(longer.as_mut()).await.is_pending());
    tokio::time::advance(Duration::from_secs(10)).await;
    assert!(poll_once(timed.as_mut()).await.is_pending());
    assert!(
        !task.is_finished(),
        "abort request must precede actual task destruction"
    );
    drop(timed);
    let mut retry = Box::pin(source.shutdown());
    assert!(poll_once(retry.as_mut()).await.is_pending());
    longer.await.unwrap();
    assert!(task.is_finished());
    retry.await;
    destroyed.await.unwrap();
    assert!(release.send(()).is_err());
    source.shutdown_configured().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn per_caller_deadlines_return_only_after_join() {
    let (source, release, destroyed) = controlled(None);
    let task = observer(&source);
    let mut short = Box::pin(source.shutdown_with_timeout(Duration::from_secs(10)));
    let mut long = Box::pin(source.shutdown_with_timeout(Duration::from_secs(30)));
    assert!(poll_once(short.as_mut()).await.is_pending());
    assert!(poll_once(long.as_mut()).await.is_pending());
    tokio::time::advance(Duration::from_secs(10)).await;
    assert!(poll_once(short.as_mut()).await.is_pending());
    assert!(!task.is_finished());
    assert!(matches!(short.await, Err(SourceError::ShutdownTimeout)));
    assert!(task.is_finished());
    long.await.unwrap();
    destroyed.await.unwrap();
    drop(release);
    source.shutdown_with_timeout(Duration::ZERO).await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn retry_backoff_cancels_and_panic_preserves_completion_policy() {
    for panic_after_release in [false, true] {
        let server = server(false);
        let Gate {
            factory,
            entered,
            release,
            dropped,
        } = gated(Arc::clone(&server.factory), panic_after_release);
        let source = build(factory, None).await;
        entered.await.unwrap();
        let task = observer(&source);
        release.send(()).unwrap();
        dropped.await.unwrap(); // same poll enters backoff or unwinds the supervisor
        if panic_after_release {
            finished(&task).await;
        }
        source.shutdown().await;
        assert!(task.is_finished());
        assert!(matches!(source.bundle_set(), Err(SourceError::Closed)));
        assert!(matches!(
            source.updated().changed().await,
            Err(SourceError::Closed)
        ));
        source.shutdown_with_timeout(Duration::ZERO).await.unwrap();
    }
}

#[tokio::test]
async fn pre_first_poll_abort_closes_getters_and_subscribers() {
    let server = server(false);
    let source = build(Arc::clone(&server.factory), None).await;
    assert_eq!(server.calls.load(Ordering::SeqCst), 1);
    assert!(!source.is_healthy());
    let task = observer(&source);
    let mut updates = source.updated();
    task.abort();
    finished(&task).await;
    assert!(source.state().is_closed());
    assert!(matches!(source.bundle_set(), Err(SourceError::Closed)));
    assert!(matches!(updates.changed().await, Err(SourceError::Closed)));
    assert!(matches!(
        updates.wait_for(|_| true).await,
        Err(SourceError::Closed)
    ));
    source.shutdown().await;
}

#[test]
fn runtime_teardown_before_first_poll_preserves_final_permission() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (source, task) = runtime.block_on(async {
        let server = server(false);
        let source = build(Arc::clone(&server.factory), None).await;
        assert_eq!(server.calls.load(Ordering::SeqCst), 1);
        let task = observer(&source);
        (source, task)
    });
    drop(runtime);
    assert!(task.is_finished());
    assert!(source.state().is_closed());
    assert!(source.state().withdrawal().is_none());
    assert!(!source.is_healthy());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        assert!(matches!(source.bundle_set(), Err(SourceError::Closed)));
        assert!(matches!(
            source.updated().changed().await,
            Err(SourceError::Closed)
        ));
        assert!(matches!(
            source.updated().wait_for(|_| true).await,
            Err(SourceError::Closed)
        ));
        source.shutdown().await;
    });
}

#[tokio::test]
async fn final_public_drop_during_owned_clone_shutdown_releases_inner() {
    let server = server(false);
    let Gate {
        factory,
        entered,
        release,
        dropped,
    } = gated(Arc::clone(&server.factory), false);
    let source = build(factory, None).await;
    entered.await.unwrap();
    let task = observer(&source);
    let weak = Arc::downgrade(&source.inner);
    let owned = source.clone();
    let mut shutdown = Box::pin(async move {
        owned.shutdown().await;
    });
    assert!(poll_once(shutdown.as_mut()).await.is_pending());
    drop(source);
    drop(shutdown);
    finished(&task).await;
    dropped.await.unwrap();
    assert_eq!(weak.strong_count(), 0);
    assert!(release.send(()).is_err());
}

struct LifecycleMetrics {
    errors: std::sync::atomic::AtomicUsize,
    reconnects: std::sync::atomic::AtomicUsize,
    panic_on_join: bool,
}

impl MetricsRecorder for LifecycleMetrics {
    fn record_update(&self) {}
    fn record_reconnect(&self) {
        self.reconnects.fetch_add(1, Ordering::SeqCst);
    }
    fn record_error(&self, kind: MetricsErrorKind) {
        self.errors.fetch_add(1, Ordering::SeqCst);
        assert!(
            !(self.panic_on_join && kind == MetricsErrorKind::SupervisorJoinFailed),
            "controlled join diagnostic failure"
        );
    }
}

#[tokio::test]
async fn diagnostic_panic_cannot_consume_persisted_completion() {
    use futures::FutureExt as _;
    let metrics = Arc::new(LifecycleMetrics {
        errors: std::sync::atomic::AtomicUsize::new(0),
        reconnects: std::sync::atomic::AtomicUsize::new(0),
        panic_on_join: true,
    });
    let (source, release, destroyed) =
        controlled_with_metrics(None, Some(Arc::<LifecycleMetrics>::clone(&metrics)));
    let task = observer(&source);
    task.abort();
    finished(&task).await;
    let result = std::panic::AssertUnwindSafe(source.shutdown())
        .catch_unwind()
        .await;
    assert!(
        result.is_err(),
        "the diagnostic deliberately violates the callback contract"
    );
    assert!(task.is_finished());
    source.shutdown_with_timeout(Duration::ZERO).await.unwrap();
    assert_eq!(
        metrics.errors.load(Ordering::SeqCst),
        1,
        "completed failure diagnostics run only once"
    );
    destroyed.await.unwrap();
    drop(release);
}

#[tokio::test]
async fn cancellation_before_setup_and_between_phases_does_not_retry_or_record_error() {
    for before_first_poll in [true, false] {
        let server = server(false);
        let token_slot = Arc::new(std::sync::Mutex::new(None::<CancellationToken>));
        let token_in_factory = Arc::clone(&token_slot);
        let initial = Arc::clone(&server.factory);
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let factory_calls = Arc::clone(&calls);
        let factory: Factory = Arc::new(move || {
            if factory_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                initial()
            } else {
                // Complete creation and cancellation in one poll. Stream opening
                // must never start after this phase observed cancellation.
                token_in_factory.lock().unwrap().as_ref().unwrap().cancel();
                let channel =
                    tonic::transport::Endpoint::from_static("http://127.0.0.1:1").connect_lazy();
                Box::pin(async move {
                    Ok(WorkloadApiClient::new_with_channel(
                        "tcp://127.0.0.1:1".parse().unwrap(),
                        channel,
                    ))
                })
            }
        });
        let metrics = Arc::new(LifecycleMetrics {
            errors: std::sync::atomic::AtomicUsize::new(0),
            reconnects: std::sync::atomic::AtomicUsize::new(0),
            panic_on_join: false,
        });
        let source = Source::builder()
            .client_factory(factory)
            .metrics(Arc::<LifecycleMetrics>::clone(&metrics))
            .build()
            .await
            .unwrap();
        *token_slot.lock().unwrap() = Some(source.inner.cancel.clone());
        let task = observer(&source);
        if before_first_poll {
            source.inner.cancel.cancel();
        }
        finished(&task).await;
        source.shutdown().await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            if before_first_poll { 1 } else { 2 }
        );
        assert_eq!(server.calls.load(Ordering::SeqCst), 1);
        assert_eq!(metrics.errors.load(Ordering::SeqCst), 0);
        assert_eq!(metrics.reconnects.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn final_public_drop_before_start_and_one_clone_control() {
    let server = server(false);
    let source = build(Arc::clone(&server.factory), None).await;
    assert_eq!(server.calls.load(Ordering::SeqCst), 1);
    let task = observer(&source);
    let token = source.inner.cancel.clone();
    let mut updates = source.updated();
    let clone = source.clone();
    drop(source);
    assert!(!token.is_cancelled());
    assert!(!task.is_finished());
    drop(clone);
    assert!(token.is_cancelled());
    finished(&task).await;
    assert_eq!(server.calls.load(Ordering::SeqCst), 1);
    assert!(matches!(updates.changed().await, Err(SourceError::Closed)));
}

#[tokio::test]
async fn withdrawal_and_recovery_remain_authoritative_after_join() {
    for recover in [false, true] {
        let server = server(false);
        let source = build(Arc::clone(&server.factory), None).await;
        // No task has polled yet: use the source's actual publication methods
        // at a deterministic cancellation/publication boundary.
        let initial = source.inner.snapshot.load_full();
        source
            .inner
            .withdraw(&WorkloadApiError::PermissionDenied("withdrawn".into()));
        if recover {
            restore(&source, &initial);
        }
        let expected = source.state();
        let task = observer(&source);
        source.shutdown().await;
        assert!(task.is_finished());
        let final_state = source.state();
        assert!(final_state.is_closed());
        assert_eq!(final_state.revision(), expected.revision());
        assert_eq!(final_state.withdrawal().is_none(), recover);
        assert_eq!(source.updated().last(), if recover { 2 } else { 1 });
    }
}

#[test]
fn synchronous_callback_must_return_before_abort_join_completes() {
    let (source_tx, source_rx) = std::sync::mpsc::channel();
    let (entry_tx, entry_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let thread = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let server = server(false);
            let initial = Arc::clone(&server.factory);
            let gate = std::sync::Mutex::new(Some((entry_tx, release_rx)));
            let calls = std::sync::atomic::AtomicUsize::new(0);
            let factory: Factory = Arc::new(move || {
                if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    initial()
                } else {
                    let (entry, release) = gate.lock().unwrap().take().unwrap();
                    entry.send(()).unwrap();
                    // A watchdog/disconnection also releases this callback on test failure.
                    release.recv_timeout(Duration::from_secs(5)).unwrap();
                    Box::pin(std::future::pending())
                }
            });
            source_tx.send(build(factory, None).await).unwrap();
            let _result = stop_rx.await;
        });
    });
    let source = source_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    entry_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        tokio::time::pause();
        let task = observer(&source);
        let mut timed = Box::pin(source.shutdown_with_timeout(Duration::from_secs(10)));
        assert!(poll_once(timed.as_mut()).await.is_pending());
        // Drive the paused timer wheel past the grace deadline before polling
        // again. Advancing Instant alone does not deliver an expired timer.
        tokio::time::sleep(Duration::from_secs(11)).await;
        assert!(poll_once(timed.as_mut()).await.is_pending());
        assert!(!task.is_finished());
        let mut concurrent = Box::pin(source.shutdown());
        assert!(poll_once(concurrent.as_mut()).await.is_pending());
        release_tx.send(()).unwrap();
        assert!(matches!(timed.await, Err(SourceError::ShutdownTimeout)));
        assert!(task.is_finished());
        concurrent.await;
    });
    stop_tx.send(()).unwrap();
    thread.join().unwrap();
}
