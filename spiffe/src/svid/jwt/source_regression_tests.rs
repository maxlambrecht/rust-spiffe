//! Signed verification through a real source, with controlled gRPC updates and clock.

use super::*;
use crate::jwt_source::{JwtSourceError, MetricsErrorKind, MetricsRecorder};
use crate::workload_api::pb::workload::{JwtBundlesRequest, JwtBundlesResponse};
use crate::{JwtSource, WorkloadApiClient};
use std::collections::HashMap;
use tokio::sync::mpsc;

type Item = Result<JwtBundlesResponse, tonic::Status>;
type StreamSender = mpsc::UnboundedSender<Item>;

struct Errors(mpsc::UnboundedSender<MetricsErrorKind>);
impl MetricsRecorder for Errors {
    fn record_update(&self) {}
    fn record_reconnect(&self) {}
    fn record_error(&self, kind: MetricsErrorKind) {
        self.0.send(kind).unwrap();
    }
}

struct Server(tokio::task::JoinHandle<()>);
impl Drop for Server {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn receive<T>(rx: &mut mpsc::UnboundedReceiver<T>) -> T {
    tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .unwrap()
        .unwrap()
}

async fn source(
    initial: JwtBundlesResponse,
) -> (
    JwtSource,
    mpsc::UnboundedReceiver<StreamSender>,
    mpsc::UnboundedReceiver<MetricsErrorKind>,
    Server,
) {
    let (rpc_tx, mut rpc_rx) = mpsc::unbounded_channel();
    let service = tower::service_fn(
        move |req: tonic::codegen::http::Request<tonic::body::Body>| {
            assert_eq!(req.uri().path(), "/SpiffeWorkloadAPI/FetchJWTBundles");
            let rpc_tx = rpc_tx.clone();
            async move {
                let handler = tower::service_fn(move |_: tonic::Request<JwtBundlesRequest>| {
                    let (tx, rx) = mpsc::unbounded_channel::<Item>();
                    rpc_tx.send(tx).unwrap();
                    async move {
                        let stream = futures::stream::unfold(rx, async |mut rx| {
                            rx.recv().await.map(|item| (item, rx))
                        });
                        Ok::<_, tonic::Status>(tonic::Response::new(stream))
                    }
                });
                Ok::<_, std::convert::Infallible>(
                    tonic::server::Grpc::new(tonic_prost::ProstCodec::default())
                        .server_streaming(handler, req)
                        .await,
                )
            }
        },
    );
    let (io_tx, io_rx) = mpsc::unbounded_channel::<tokio::io::DuplexStream>();
    let incoming = futures::stream::unfold(io_rx, async |mut rx| {
        rx.recv().await.map(|io| (Ok::<_, std::io::Error>(io), rx))
    });
    let server = Server(tokio::spawn(async move {
        tonic::transport::Server::builder()
            .serve_with_incoming(service, incoming)
            .await
            .unwrap();
    }));
    let channel = tonic::transport::Endpoint::from_static("http://localhost")
        .connect_with_connector(tower::service_fn(move |_| {
            let (a, b) = tokio::io::duplex(64 * 1024);
            io_tx.send(b).unwrap();
            async move { Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(a)) }
        }))
        .await
        .unwrap();
    let client = WorkloadApiClient::new_with_channel("tcp://127.0.0.1:1".parse().unwrap(), channel);
    let (error_tx, error_rx) = mpsc::unbounded_channel();
    let builder = JwtSource::builder()
        .client_factory(Arc::new(move || {
            let client = client.clone();
            Box::pin(async move { Ok(client) })
        }))
        .metrics(Arc::new(Errors(error_tx)))
        .resource_limits(crate::JwtResourceLimits::new(Some(1), Some(4096)))
        .reconnect_backoff(Duration::ZERO, Duration::ZERO)
        .initial_sync_timeout(Duration::from_secs(5));
    let (built, ()) = tokio::join!(builder.build(), async {
        receive(&mut rpc_rx).await.send(Ok(initial)).unwrap();
    });
    (built.unwrap(), rpc_rx, error_rx, server)
}

fn response(bundles: &JwtBundleSet) -> JwtBundlesResponse {
    JwtBundlesResponse {
        bundles: bundles
            .iter()
            .map(|(td, bundle)| {
                let keys: Vec<serde_json::Value> = bundle
                    .jwt_authorities()
                    .map(|authority| serde_json::from_slice(authority.jwk_json()).unwrap())
                    .collect();
                (
                    td.to_string(),
                    serde_json::to_vec(&serde_json::json!({"keys": keys}))
                        .unwrap()
                        .into(),
                )
            })
            .collect(),
    }
}

fn verify(token: &str, source: &JwtSource) -> Result<JwtSvid, JwtSvidError> {
    JwtSvid::parse_and_validate_with_clock(token, source, &["audience"], || {
        UNIX_EPOCH + Duration::from_secs(u64::try_from(N).unwrap())
    })
}

fn authority_field(
    mut response: JwtBundlesResponse,
    field: &str,
    value: serde_json::Value,
) -> JwtBundlesResponse {
    let bytes = response.bundles.get_mut("example.org").unwrap();
    let mut jwks: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    let jwk = jwks
        .get_mut("keys")
        .unwrap()
        .as_array_mut()
        .unwrap()
        .first_mut()
        .unwrap()
        .as_object_mut()
        .unwrap();
    let _previous = jwk.insert(field.into(), value);
    *bytes = serde_json::to_vec(&jwks).unwrap().into();
    response
}

async fn revision(updates: &mut crate::JwtSourceUpdates, expected: u64) {
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), updates.changed())
            .await
            .unwrap()
            .unwrap(),
        expected
    );
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "keeps the ordered cross-fix transition sequence and its assertions together"
)]
async fn signed_jwt_policy_survives_withdrawal_identical_recovery_and_key_rotation() {
    let a = Fixture::es256();
    let b = Fixture::es256();
    let initial = response(&a.bundles);
    let (source, mut rpcs, mut errors, _server) = source(initial.clone()).await;
    let mut stream = receive(&mut rpcs).await;
    let valid = a.token(N + 600, None);
    let copied = source.bundle_set().unwrap();
    verify(&valid, &source).unwrap();
    JwtSvid::parse_and_validate(&valid, &source, &["audience"]).unwrap();
    let mut updates = source.updated();

    stream
        .send(Err(tonic::Status::permission_denied("withdrawn")))
        .unwrap();
    revision(&mut updates, 1).await;
    assert_eq!(receive(&mut errors).await, MetricsErrorKind::StreamError);
    assert!(
        matches!(verify(&valid, &source), Err(JwtSvidError::BundleSourceError(error))
        if matches!(error.downcast_ref::<JwtSourceError>(), Some(JwtSourceError::Withdrawn(_))))
    );
    JwtSvid::parse_and_validate(&valid, copied.as_ref(), &["audience"]).unwrap();

    stream = receive(&mut rpcs).await;
    stream
        .send(Err(tonic::Status::unavailable("temporary")))
        .unwrap();
    assert_eq!(receive(&mut errors).await, MetricsErrorKind::StreamError);
    assert_eq!(source.state().revision(), 1);
    stream = receive(&mut rpcs).await;
    stream
        .send(Ok(JwtBundlesResponse {
            bundles: HashMap::from([("example.org".into(), b"invalid JWKS".to_vec().into())]),
        }))
        .unwrap();
    assert_eq!(receive(&mut errors).await, MetricsErrorKind::StreamError);
    assert!(source.state().withdrawal().is_some());
    assert_eq!(source.state().revision(), 1);

    stream = receive(&mut rpcs).await;
    stream.send(Ok(JwtBundlesResponse::default())).unwrap();
    assert_eq!(receive(&mut errors).await, MetricsErrorKind::UpdateRejected);
    assert_eq!(source.state().revision(), 1);
    assert!(source.state().withdrawal().is_some());
    let oversized = authority_field(
        initial.clone(),
        "extension",
        serde_json::json!("x".repeat(5000)),
    );
    stream.send(Ok(oversized)).unwrap();
    assert_eq!(
        receive(&mut errors).await,
        MetricsErrorKind::LimitMaxBundleJwksBytes
    );
    assert_eq!(receive(&mut errors).await, MetricsErrorKind::UpdateRejected);
    assert_eq!(source.state().revision(), 1);
    assert!(source.state().withdrawal().is_some());
    stream.send(Ok(initial.clone())).unwrap();
    revision(&mut updates, 2).await;
    verify(&valid, &source).unwrap();
    assert_kind(
        verify(&a.token(N + 600, Some("2000000001")), &source),
        JwtVerificationErrorKind::NotYetValid,
    );
    assert_kind(
        verify(&a.token(N, None), &source),
        JwtVerificationErrorKind::Expired,
    );
    let forbidden = a.sign(
        JwtAlg::ES256,
        r#"{"alg":"ES256","kid":"k1","crit":[]}"#,
        &payload(N + 600, None),
    );
    assert!(matches!(
        verify(&forbidden, &source),
        Err(JwtSvidError::InvalidJoseHeader(_))
    ));

    stream.send(Ok(response(&b.bundles))).unwrap();
    revision(&mut updates, 3).await;
    assert_kind(
        verify(&valid, &source),
        JwtVerificationErrorKind::InvalidSignature,
    );
    let rotated = b.token(N + 600, None);
    verify(&rotated, &source).unwrap();
    let restricted = authority_field(response(&b.bundles), "alg", serde_json::json!("ES384"));
    stream.send(Ok(restricted)).unwrap();
    revision(&mut updates, 4).await;
    assert!(matches!(
        verify(&rotated, &source),
        Err(JwtSvidError::AuthorityAlgorithmMismatch { .. })
    ));

    // A structurally admitted weak authority must still fail at verification.
    let key = Rsa::generate(1024).unwrap();
    let weak = Fixture::new(
        PKey::from_rsa(key.clone()).unwrap(),
        &serde_json::json!({
            "kid":"k1", "kty":"RSA", "n":b64(&key.n().to_vec()), "e":b64(&key.e().to_vec())
        }),
    );
    let weak_token = weak.sign(
        JwtAlg::RS256,
        r#"{"alg":"RS256","kid":"k1"}"#,
        &payload(N + 600, None),
    );
    stream.send(Ok(response(&weak.bundles))).unwrap();
    revision(&mut updates, 5).await;
    assert!(matches!(
        verify(&weak_token, &source),
        Err(JwtSvidError::WeakRsaAuthority(1024))
    ));
    stream.send(Ok(initial)).unwrap();
    revision(&mut updates, 6).await;
    verify(&valid, &source).unwrap();
    source.shutdown().await;
    assert!(source.state().is_closed());
}
