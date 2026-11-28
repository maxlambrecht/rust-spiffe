// Included for each source after `source_startup_tests.rs`; covers the default
// `SPIFFE_ENDPOINT_SOCKET` client setup.
//
// The environment is process-wide and the test harness runs tests on many threads,
// so no test mutates the environment of the test process. Each case re-runs itself
// as the only test in a child process of this test binary, with the variable set
// (or removed) by `Command::env` at spawn. Only the lifetime test changes the variable
// after start-up, in that dedicated child, with the preconditions documented on
// `set_endpoint_env_single_threaded`.

use crate::workload_api::endpoint::WORKLOAD_API_ENDPOINT_ENV;
use std::ffi::OsStr;
#[cfg(unix)]
use std::ffi::OsString;

/// Names the test whose body a child process runs.
const ENV_CHILD: &str = "SPIFFE_SOURCE_ENV_TEST_CHILD";
/// Case-specific input passed to a child process.
const ENV_CASE: &str = "SPIFFE_SOURCE_ENV_TEST_CASE";

/// Runs `body` in a child process of this test binary, as its only test, with
/// `SPIFFE_ENDPOINT_SOCKET` set to `endpoint` or removed for `None`.
fn in_env_child(test: &str, endpoint: Option<&OsStr>, case: &str, body: impl FnOnce()) {
    if std::env::var_os(ENV_CHILD).as_deref() == Some(OsStr::new(test)) {
        body();
        return;
    }
    let (_crate, module) = module_path!().split_once("::").unwrap();
    let path = format!("{module}::{test}");
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args([path.as_str(), "--exact", "--test-threads=1", "--nocapture"])
        .env(ENV_CHILD, test)
        .env(ENV_CASE, case)
        .env_remove(WORKLOAD_API_ENDPOINT_ENV);
    if let Some(endpoint) = endpoint {
        command.env(WORKLOAD_API_ENDPOINT_ENV, endpoint);
    }
    let output = command.output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("test result: ok. 1 passed"),
        "child {path} ({case}) failed:\n{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn child_case() -> String {
    std::env::var(ENV_CASE).unwrap()
}

/// In a child process of a test that loops over cases, skips all but its own case.
fn is_other_case_in_child(test: &str, case: &str) -> bool {
    std::env::var_os(ENV_CHILD).as_deref() == Some(OsStr::new(test)) && child_case() != case
}

/// A current-thread runtime runs every task on the calling thread.
fn current_thread_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

#[test]
fn env_endpoint_unset_fails_on_first_poll_without_retry_or_metrics() {
    in_env_child(
        "env_endpoint_unset_fails_on_first_poll_without_retry_or_metrics",
        None,
        "unset",
        || {
            current_thread_runtime().block_on(async {
                let (tx, mut errors) = mpsc::channel(128);
                let mut build = Box::pin(Source::builder().metrics(Arc::new(Metrics(tx))).build());
                let result = poll_once(build.as_mut()).await;
                assert!(
                    matches!(
                        result,
                        std::task::Poll::Ready(Err(SourceError::Source(
                            WorkloadApiError::MissingEndpointSocket
                        )))
                    ),
                    "unset endpoint must fail on first poll: {result:?}"
                );
                assert!(errors.try_recv().is_err(), "no client attempts or metrics");
            });
        },
    );
}

#[test]
fn env_endpoint_invalid_syntax_fails_on_first_poll_without_echoing_user_info() {
    for (raw, kind) in [
        ("/tmp/agent.sock", "parse"),
        ("invalid://fixed", "scheme"),
        ("unix://host/socket", "authority"),
        ("tcp://user:secret@127.0.0.1:80", "userinfo"),
    ] {
        if is_other_case_in_child(
            "env_endpoint_invalid_syntax_fails_on_first_poll_without_echoing_user_info",
            kind,
        ) {
            continue;
        }
        in_env_child(
            "env_endpoint_invalid_syntax_fails_on_first_poll_without_echoing_user_info",
            Some(OsStr::new(raw)),
            kind,
            || {
                current_thread_runtime().block_on(async {
                    let (tx, mut errors) = mpsc::channel(128);
                    let mut build = Box::pin(
                        Source::builder()
                            .metrics(Arc::new(Metrics(tx)))
                            .initial_sync_timeout(Duration::from_secs(60))
                            .build(),
                    );
                    let result = poll_once(build.as_mut()).await;
                    let std::task::Poll::Ready(Err(error)) = result else {
                        panic!("invalid endpoint must fail on first poll: {result:?}");
                    };
                    let SourceError::Source(WorkloadApiError::Endpoint(endpoint)) = &error else {
                        panic!("expected an endpoint configuration error: {error:?}");
                    };
                    match (child_case().as_str(), endpoint) {
                        ("parse", EndpointError::Parse(_))
                        | ("scheme", EndpointError::InvalidScheme)
                        | ("authority", EndpointError::UnixAuthorityNotAllowed)
                        | ("userinfo", EndpointError::HasUserInfo) => {}
                        (case, other) => panic!("unexpected classification for {case}: {other:?}"),
                    }
                    for text in [error.to_string(), format!("{error:?}")] {
                        assert!(!text.contains("secret"), "user info leaked: {text}");
                    }
                    assert!(errors.try_recv().is_err(), "no client attempts or metrics");
                });
            },
        );
    }
}

#[cfg(unix)]
#[test]
fn env_endpoint_not_unicode_fails_on_first_poll() {
    use std::os::unix::ffi::OsStrExt as _;
    in_env_child(
        "env_endpoint_not_unicode_fails_on_first_poll",
        Some(OsStr::from_bytes(b"unix:/tmp/agent\xff.sock")),
        "not-unicode",
        || {
            current_thread_runtime().block_on(async {
                let mut build = Box::pin(Source::builder().build());
                let result = poll_once(build.as_mut()).await;
                assert!(
                    matches!(
                        result,
                        std::task::Poll::Ready(Err(SourceError::Source(
                            WorkloadApiError::NotUnicodeEndpointSocket(_)
                        )))
                    ),
                    "non-Unicode endpoint must fail on first poll: {result:?}"
                );
            });
        },
    );
}

#[cfg(unix)]
#[test]
fn env_endpoint_valid_but_absent_socket_retries_until_timeout_or_available() {
    let socket = support::UnixSocket::new();
    in_env_child(
        "env_endpoint_valid_but_absent_socket_retries_until_timeout_or_available",
        Some(OsStr::new(&socket.endpoint())),
        &socket.0.display().to_string(),
        || {
            let socket = support::UnixSocket(child_case().into());
            current_thread_runtime().block_on(async {
                let error = watchdog(
                    Source::builder()
                        .reconnect_backoff(Duration::from_millis(10), Duration::from_millis(10))
                        .initial_sync_timeout(Duration::from_millis(200))
                        .build(),
                )
                .await
                .unwrap_err();
                let cause = assert_timeout_wraps_cause(&error);
                assert!(
                    matches!(cause, SourceError::Source(WorkloadApiError::Transport(_))),
                    "an unavailable valid endpoint is an infrastructure failure: {cause:?}"
                );

                let (tx, mut errors) = mpsc::channel(128);
                let build = Source::builder()
                    .reconnect_backoff(Duration::from_millis(10), Duration::from_millis(10))
                    .metrics(Arc::new(Metrics(tx)))
                    .build();
                tokio::pin!(build);
                tokio::select! {
                    kind = errors.recv() => assert_eq!(kind.unwrap(), MetricsErrorKind::ClientCreation),
                    _ = &mut build => panic!("socket is absent"),
                }
                let _server = support::serve_unix(&socket);
                let source = watchdog(build).await.unwrap();
                source.bundle_set().unwrap();
                watchdog(source.shutdown()).await;
            });
        },
    );
}

#[test]
fn env_endpoint_unset_is_not_read_when_endpoint_or_factory_is_configured() {
    for case in ["endpoint", "factory"] {
        if is_other_case_in_child(
            "env_endpoint_unset_is_not_read_when_endpoint_or_factory_is_configured",
            case,
        ) {
            continue;
        }
        in_env_child(
            "env_endpoint_unset_is_not_read_when_endpoint_or_factory_is_configured",
            None,
            case,
            || {
                current_thread_runtime().block_on(async {
                    let server = support::server(vec![Step::Valid]).await;
                    let builder = Source::builder();
                    let builder = if child_case() == "endpoint" {
                        builder.endpoint(&server.endpoint)
                    } else {
                        let endpoint = server.endpoint.clone();
                        let factory: Factory = Arc::new(move || {
                            Box::pin(crate::WorkloadApiClient::connect_to(endpoint.clone()))
                        });
                        builder.client_factory(factory)
                    };
                    let source = watchdog(builder.build()).await.unwrap();
                    source.bundle_set().unwrap();
                    watchdog(source.shutdown()).await;
                });
            },
        );
    }
}

/// Points `SPIFFE_ENDPOINT_SOCKET` at `value` in an env-test child process.
///
/// Preconditions, which make the mutation sound rather than merely serialized:
/// - the process is a child running exactly one test (`--exact`, one test thread),
///   so the only other thread is the harness main thread blocked on that test's result;
/// - the caller runs no runtime: every task of its current-thread runtime is
///   suspended, and that runtime has started no worker or blocking threads.
///
/// On Linux the thread count is checked before mutating.
#[cfg(unix)]
#[expect(
    unsafe_code,
    reason = "a single-threaded child process changes SPIFFE_ENDPOINT_SOCKET after build"
)]
fn set_endpoint_env_single_threaded(value: &str) {
    assert!(
        std::env::var_os(ENV_CHILD).is_some(),
        "must only run in an env-test child process"
    );
    #[cfg(target_os = "linux")]
    {
        let threads = std::fs::read_dir("/proc/self/task").unwrap().count();
        assert_eq!(
            threads, 2,
            "only the harness main thread and this test thread may exist"
        );
    }
    // SAFETY: see the preconditions above. No other thread can read or write the
    // environment while this call runs.
    unsafe {
        std::env::set_var(WORKLOAD_API_ENDPOINT_ENV, value);
    }
}

/// Builds a source from `SPIFFE_ENDPOINT_SOCKET` pointing at server A, repoints the
/// variable at server B, then runs `check` with the source and both servers.
#[cfg(unix)]
fn after_env_endpoint_change(
    test: &str,
    steps_a: Vec<Step>,
    check: impl AsyncFnOnce(Source, support::Server, support::Server),
) {
    let a = support::UnixSocket::new();
    let b = support::UnixSocket::new();
    in_env_child(
        test,
        Some(OsStr::new(&a.endpoint())),
        &b.0.display().to_string(),
        || {
            let a = support::UnixSocket(
                std::env::var(WORKLOAD_API_ENDPOINT_ENV)
                    .unwrap()
                    .strip_prefix("unix:")
                    .unwrap()
                    .into(),
            );
            let b = support::UnixSocket(OsString::from(child_case()).into());
            let runtime = current_thread_runtime();
            let (source, server_a, server_b) = runtime.block_on(async {
                let server_a = support::serve_unix_steps(&a, steps_a);
                let server_b = support::serve_unix_steps(&b, vec![Step::Valid]);
                let source = watchdog(
                    Source::builder()
                        .reconnect_backoff(Duration::from_millis(10), Duration::from_millis(10))
                        .build(),
                )
                .await
                .unwrap();
                (source, server_a, server_b)
            });
            // No task runs between leaving and re-entering the runtime; the supervisor
            // has not yet created its first client.
            set_endpoint_env_single_threaded(&b.endpoint());
            runtime.block_on(check(source, server_a, server_b));
        },
    );
}

#[cfg(unix)]
#[test]
fn env_endpoint_is_resolved_once_for_the_source_lifetime() {
    // A: construction, then a supervisor stream that fails after one update, then
    // the reconnected stream. B: what a re-read of the variable would reach.
    after_env_endpoint_change(
        "env_endpoint_is_resolved_once_for_the_source_lifetime",
        vec![
            Step::Valid,
            Step::ValidThenTrailers(tonic::Code::Unavailable),
            Step::Valid,
        ],
        async |source, mut a, mut b| {
            let rpc = format!("/SpiffeWorkloadAPI/{RPC}");
            for attempt in ["construction", "supervisor", "reconnect"] {
                assert_eq!(
                    watchdog(a.calls.recv()).await.unwrap(),
                    rpc,
                    "{attempt} must use the endpoint resolved at build"
                );
            }
            assert!(
                matches!(b.calls.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
                "a later SPIFFE_ENDPOINT_SOCKET value must not be used"
            );
            source.bundle_set().unwrap();
            watchdog(source.shutdown()).await;
        },
    );
}
