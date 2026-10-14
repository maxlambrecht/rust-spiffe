//! Scripted wire responses for terminal startup and recovery regressions.
#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "Test setup and assertions"
)]

use super::pb::workload::{JwtBundlesResponse, X509svid, X509svidResponse};
use futures::StreamExt as _;
use std::{
    collections::VecDeque,
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::mpsc;
use tonic::codegen::http;

#[derive(Clone, Copy, Debug)]
pub(crate) enum Step {
    Headers(tonic::Code),
    Trailers(tonic::Code),
    ValidThenTrailers(tonic::Code),
    NoIdentity,
    Eof,
    Valid,
    Malformed,
}

pub(crate) struct Server {
    pub endpoint: String,
    pub calls: mpsc::Receiver<String>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub(crate) async fn watchdog<F: std::future::Future>(f: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(3), f)
        .await
        .expect("startup test watchdog")
}

fn status(code: tonic::Code, stage: &'static str) -> tonic::Status {
    let mut s = tonic::Status::with_details(
        code,
        "required RPC unavailable",
        b"startup-probe".as_slice().into(),
    );
    s.metadata_mut()
        .insert("failure-stage", stage.parse().unwrap());
    s
}

#[derive(Clone, PartialEq, prost::Message)]
#[expect(clippy::empty_structs_with_brackets, reason = "prost empty message")]
struct Empty {}

async fn reply<T>(
    req: http::Request<tonic::body::Body>,
    step: Step,
    valid: T,
) -> http::Response<tonic::body::Body>
where
    T: prost::Message + Default + Clone + Send + Sync + 'static,
{
    let handler = tower::service_fn(move |_: tonic::Request<Empty>| {
        let valid = valid.clone();
        async move {
            type Stream<T> = Pin<Box<dyn futures::Stream<Item = Result<T, tonic::Status>> + Send>>;
            let stream: Stream<T> = match step {
                Step::Headers(code) => return Err(status(code, "headers")),
                Step::NoIdentity => {
                    return Err(tonic::Status::permission_denied("no identity issued"))
                }
                Step::Trailers(code) => {
                    Box::pin(futures::stream::iter([Err(status(code, "trailers"))]))
                }
                Step::ValidThenTrailers(code) => Box::pin(futures::stream::iter([
                    Ok(valid),
                    Err(status(code, "trailers")),
                ])),
                Step::Eof => Box::pin(futures::stream::empty()),
                Step::Valid => {
                    Box::pin(futures::stream::iter([Ok(valid)]).chain(futures::stream::pending()))
                }
                Step::Malformed => Box::pin(futures::stream::iter([Ok(T::default())])),
            };
            Ok(tonic::Response::new(stream))
        }
    });
    tonic::server::Grpc::new(tonic_prost::ProstCodec::default())
        .server_streaming(handler, req)
        .await
}

pub(crate) fn x509_response() -> X509svidResponse {
    X509svidResponse {
        svids: vec![X509svid {
            spiffe_id: "spiffe://example.org/service".into(),
            x509_svid: include_bytes!("../../tests/testdata/svid/x509/1-svid-chain.der")
                .to_vec()
                .into(),
            x509_svid_key: include_bytes!("../../tests/testdata/svid/x509/1-key.der")
                .to_vec()
                .into(),
            bundle: include_bytes!("../../tests/testdata/bundle/x509/cert1.der")
                .to_vec()
                .into(),
            hint: String::new(),
        }],
        ..Default::default()
    }
}

pub(crate) fn jwt_response() -> JwtBundlesResponse {
    JwtBundlesResponse {
        bundles: std::collections::HashMap::from([(
            "example.org".into(),
            br#"{"keys":[{"kid":"probe","kty":"EC","crv":"P-256","x":"unused","y":"unused"}]}"#
                .to_vec()
                .into(),
        )]),
    }
}

pub(crate) fn serve(listener: tokio::net::TcpListener, steps: Vec<Step>) -> Server {
    let endpoint = format!("tcp://{}", listener.local_addr().unwrap());
    serve_incoming(
        endpoint,
        tonic::transport::server::TcpIncoming::from(listener),
        steps,
    )
}

fn serve_incoming<I, S>(endpoint: String, incoming: S, steps: Vec<Step>) -> Server
where
    I: tokio::io::AsyncRead
        + tokio::io::AsyncWrite
        + tonic::transport::server::Connected
        + Unpin
        + Send
        + 'static,
    S: futures::Stream<Item = Result<I, std::io::Error>> + Send + 'static,
{
    let (tx, calls) = mpsc::channel(128);
    let steps = Arc::new(Mutex::new(VecDeque::from(steps)));
    let svc = tower::service_fn(move |req: http::Request<tonic::body::Body>| {
        let path = req.uri().path().to_owned();
        tx.try_send(path.clone()).unwrap();
        let step = {
            let mut steps = steps.lock().unwrap();
            if steps.len() > 1 {
                steps.pop_front().unwrap()
            } else {
                *steps.front().unwrap()
            }
        };
        async move {
            let response = match path.as_str() {
                "/SpiffeWorkloadAPI/FetchX509SVID" => reply(req, step, x509_response()).await,
                "/SpiffeWorkloadAPI/FetchJWTBundles" => reply(req, step, jwt_response()).await,
                _ => panic!("unexpected RPC: {path}"),
            };
            Ok::<_, std::convert::Infallible>(response)
        }
    });
    let task = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .serve_with_incoming(svc, incoming)
            .await
            .unwrap();
    });
    Server {
        endpoint,
        calls,
        task,
    }
}

pub(crate) async fn server(steps: Vec<Step>) -> Server {
    serve(
        tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap(),
        steps,
    )
}

#[cfg(unix)]
pub(crate) struct UnixSocket(pub std::path::PathBuf);
#[cfg(unix)]
impl UnixSocket {
    pub(crate) fn new() -> Self {
        Self(std::path::PathBuf::from(format!(
            "/tmp/spiffe-startup-{}-{}.sock",
            std::process::id(),
            fastrand::u64(..)
        )))
    }
    pub(crate) fn endpoint(&self) -> String {
        format!("unix:{}", self.0.display())
    }
}
#[cfg(unix)]
impl Drop for UnixSocket {
    fn drop(&mut self) {
        let _result = std::fs::remove_file(&self.0);
    }
}
#[cfg(unix)]
pub(crate) fn serve_unix(socket: &UnixSocket) -> Server {
    let listener = tokio::net::UnixListener::bind(&socket.0).unwrap();
    let incoming = futures::stream::unfold(listener, async |listener| {
        let io = listener.accept().await.map(|(io, _)| io);
        Some((io, listener))
    });
    serve_incoming(socket.endpoint(), incoming, vec![Step::Valid])
}
