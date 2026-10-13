//! Controlled Workload API and setup futures for source lifecycle regressions.
#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "Test-only fixtures fail immediately when setup or watchdog assertions fail"
)]
use crate::workload_api::pb::workload::{JwtBundlesResponse, X509svid, X509svidResponse};
use crate::{WorkloadApiClient, WorkloadApiError};
use futures::Future;
use futures::StreamExt as _;
use std::{
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    task::Poll,
    time::Duration,
};
use tokio::{
    io::DuplexStream,
    sync::{mpsc, oneshot},
};
pub(crate) type Factory = Arc<
    dyn Fn() -> Pin<Box<dyn Future<Output = Result<WorkloadApiClient, WorkloadApiError>> + Send>>
        + Send
        + Sync,
>;
pub(crate) struct OnDrop(pub Option<oneshot::Sender<()>>);
impl Drop for OnDrop {
    fn drop(&mut self) {
        if let Some(tx) = self.0.take() {
            let _result = tx.send(());
        }
    }
}
pub(crate) async fn poll_once<F: Future>(mut f: Pin<&mut F>) -> Poll<F::Output> {
    std::future::poll_fn(|cx| Poll::Ready(f.as_mut().poll(cx))).await
}
pub(crate) async fn finished(h: &tokio::task::AbortHandle) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while !h.is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("task completion watchdog");
}
pub(crate) struct Server {
    pub factory: Factory,
    pub calls: Arc<AtomicUsize>,
    pub headers_entered: Arc<tokio::sync::Notify>,
    pub read_entered: Arc<tokio::sync::Notify>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
#[derive(Clone, PartialEq, prost::Message)]
#[expect(
    clippy::empty_structs_with_brackets,
    reason = "prost's Message derive requires a braced empty message"
)]
struct Empty {}
#[expect(
    clippy::too_many_lines,
    reason = "Keeps both controlled RPC handlers and their signals together"
)]
pub(crate) fn server(stall_headers: bool) -> Server {
    let calls = Arc::new(AtomicUsize::new(0));
    let headers_entered = Arc::new(tokio::sync::Notify::new());
    let read_entered = Arc::new(tokio::sync::Notify::new());
    let headers_signal = Arc::clone(&headers_entered);
    let read_signal = Arc::clone(&read_entered);
    let x509_calls = Arc::new(AtomicUsize::new(0));
    let jwt_calls = Arc::new(AtomicUsize::new(0));
    let svc = tower::service_fn(
        move |req: tonic::codegen::http::Request<tonic::body::Body>| {
            let is_x = req.uri().path().ends_with("FetchX509SVID");
            let n = if is_x {
                x509_calls.fetch_add(1, Ordering::SeqCst)
            } else {
                jwt_calls.fetch_add(1, Ordering::SeqCst)
            };
            let headers_signal = Arc::clone(&headers_signal);
            let read_signal = Arc::clone(&read_signal);
            async move {
                let response = if is_x {
                    let handler = tower::service_fn(move |_: tonic::Request<Empty>| {
                        let headers_signal = Arc::clone(&headers_signal);
                        let read_signal = Arc::clone(&read_signal);
                        async move {
                            if stall_headers && n > 0 {
                                headers_signal.notify_one();
                                std::future::pending::<()>().await;
                            }
                            let x = X509svidResponse {
                                svids: vec![X509svid {
                                    spiffe_id: "spiffe://example.org/service".into(),
                                    x509_svid: include_bytes!(
                                        "../../tests/testdata/svid/x509/1-svid-chain.der"
                                    )
                                    .to_vec()
                                    .into(),
                                    x509_svid_key: include_bytes!(
                                        "../../tests/testdata/svid/x509/1-key.der"
                                    )
                                    .to_vec()
                                    .into(),
                                    bundle: include_bytes!(
                                        "../../tests/testdata/bundle/x509/cert1.der"
                                    )
                                    .to_vec()
                                    .into(),
                                    hint: String::new(),
                                }],
                                ..Default::default()
                            };
                            let tail = futures::stream::poll_fn(move |_| {
                                if n > 0 {
                                    read_signal.notify_one();
                                }
                                Poll::<Option<Result<X509svidResponse, tonic::Status>>>::Pending
                            });
                            Ok::<_, tonic::Status>(tonic::Response::new(
                                futures::stream::iter([Ok(x)]).chain(tail),
                            ))
                        }
                    });
                    tonic::server::Grpc::new(tonic_prost::ProstCodec::default())
                        .server_streaming(handler, req)
                        .await
                } else {
                    let handler = tower::service_fn(move |_: tonic::Request<Empty>| {
                        let headers_signal = Arc::clone(&headers_signal);
                        let read_signal = Arc::clone(&read_signal);
                        async move {
                            if stall_headers && n > 0 {
                                headers_signal.notify_one();
                                std::future::pending::<()>().await;
                            }
                            let j = JwtBundlesResponse {
                                bundles: std::collections::HashMap::from([(
                                    "example.org".into(),
                                    br#"{"keys":[{"kid":"probe","kty":"EC","crv":"P-256","x":"unused","y":"unused"}]}"#
                                        .to_vec()
                                        .into(),
                                )]),
                            };
                            let tail = futures::stream::poll_fn(move |_| {
                                if n > 0 {
                                    read_signal.notify_one();
                                }
                                Poll::<Option<Result<JwtBundlesResponse, tonic::Status>>>::Pending
                            });
                            Ok::<_, tonic::Status>(tonic::Response::new(
                                futures::stream::iter([Ok(j)]).chain(tail),
                            ))
                        }
                    });
                    tonic::server::Grpc::new(tonic_prost::ProstCodec::default())
                        .server_streaming(handler, req)
                        .await
                };
                Ok::<_, std::convert::Infallible>(response)
            }
        },
    );
    let (tx, rx) = mpsc::unbounded_channel::<DuplexStream>();
    let incoming = futures::stream::unfold(rx, async |mut rx| {
        rx.recv().await.map(|io| (Ok::<_, std::io::Error>(io), rx))
    });
    let task = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .serve_with_incoming(svc, incoming)
            .await
            .unwrap();
    });
    let calls_counter = Arc::clone(&calls);
    let factory: Factory = Arc::new(move || {
        calls_counter.fetch_add(1, Ordering::SeqCst);
        let tx = tx.clone();
        Box::pin(async move {
            let channel = tonic::transport::Endpoint::from_static("http://localhost")
                .connect_with_connector(tower::service_fn(move |_| {
                    let tx = tx.clone();
                    async move {
                        let (a, b) = tokio::io::duplex(64 * 1024);
                        tx.send(b).unwrap();
                        Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(a))
                    }
                }))
                .await
                .unwrap();
            Ok(WorkloadApiClient::new_with_channel(
                "tcp://127.0.0.1:1".parse().unwrap(),
                channel,
            ))
        })
    });
    Server {
        factory,
        calls,
        headers_entered,
        read_entered,
        task,
    }
}
pub(crate) struct Gate {
    pub factory: Factory,
    pub entered: oneshot::Receiver<()>,
    pub release: oneshot::Sender<()>,
    pub dropped: oneshot::Receiver<()>,
}
pub(crate) fn gated(initial: Factory, panic_after_release: bool) -> Gate {
    let (entry_tx, entered) = oneshot::channel();
    let (release, release_rx) = oneshot::channel();
    let (drop_tx, dropped) = oneshot::channel();
    let slot = Mutex::new(Some((entry_tx, release_rx, drop_tx)));
    let calls = AtomicUsize::new(0);
    let factory: Factory = Arc::new(move || {
        if calls.fetch_add(1, Ordering::SeqCst) == 0 {
            initial()
        } else {
            let (entry_tx, release_rx, drop_tx) = slot.lock().unwrap().take().unwrap();
            let drop = OnDrop(Some(drop_tx));
            Box::pin(async move {
                let _drop = drop;
                let _result = entry_tx.send(());
                let _result = release_rx.await;
                assert!(!panic_after_release, "controlled supervisor panic");
                Err(WorkloadApiError::NoIdentityIssued)
            })
        }
    });
    Gate {
        factory,
        entered,
        release,
        dropped,
    }
}
struct PendingIo {
    entered: Option<oneshot::Sender<()>>,
    dropped: Option<oneshot::Sender<()>>,
}
impl tokio::io::AsyncRead for PendingIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
}
impl tokio::io::AsyncWrite for PendingIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if let Some(tx) = self.entered.take() {
            let _result = tx.send(());
        }
        Poll::Pending
    }
    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
}
impl Drop for PendingIo {
    fn drop(&mut self) {
        if let Some(tx) = self.dropped.take() {
            let _result = tx.send(());
        }
    }
}
pub(crate) fn transport_gate(initial: Factory, handshake: bool) -> Gate {
    let (entry_tx, entered) = oneshot::channel();
    let (release, release_rx) = oneshot::channel();
    let (drop_tx, dropped) = oneshot::channel();
    let slot = Mutex::new(Some((entry_tx, release_rx, drop_tx)));
    let calls = AtomicUsize::new(0);
    let factory: Factory = Arc::new(move || {
        if calls.fetch_add(1, Ordering::SeqCst) == 0 {
            initial()
        } else {
            let (entry_tx, release_rx, drop_tx) = slot.lock().unwrap().take().unwrap();
            if handshake {
                let slot = Arc::new(Mutex::new(Some(PendingIo {
                    entered: Some(entry_tx),
                    dropped: Some(drop_tx),
                })));
                Box::pin(async move {
                    let _release = release_rx;
                    let result = tonic::transport::Endpoint::from_static("http://localhost")
                        .connect_with_connector(tower::service_fn(move |_| {
                            let io = slot.lock().unwrap().take().unwrap();
                            async { Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(io)) }
                        }))
                        .await;
                    let _error = result.unwrap_err();
                    Err(WorkloadApiError::NoIdentityIssued)
                })
            } else {
                let slot = Arc::new(Mutex::new(Some((entry_tx, release_rx, drop_tx))));
                Box::pin(async move {
                    let result = tonic::transport::Endpoint::from_static("http://localhost")
                        .connect_with_connector(tower::service_fn(move |_| {
                            let (entry_tx, release_rx, drop_tx) =
                                slot.lock().unwrap().take().unwrap();
                            let drop = OnDrop(Some(drop_tx));
                            async move {
                                let _drop = drop;
                                let _result = entry_tx.send(());
                                let _result = release_rx.await;
                                Err::<hyper_util::rt::TokioIo<PendingIo>, _>(std::io::Error::other(
                                    "released connector",
                                ))
                            }
                        }))
                        .await;
                    let _error = result.unwrap_err();
                    Err(WorkloadApiError::NoIdentityIssued)
                })
            }
        }
    });
    Gate {
        factory,
        entered,
        release,
        dropped,
    }
}
