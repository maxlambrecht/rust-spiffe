//! Public RPC regressions against generated protobuf messages over tonic/HTTP2.
use super::WorkloadApiClient;
use crate::workload_api::pb::workload::*;
use crate::WorkloadApiError;
use futures::StreamExt as _;
use std::collections::HashMap;
use tonic::codegen::http;

struct Server(tokio::task::JoinHandle<()>);
impl Drop for Server {
    fn drop(&mut self) {
        self.0.abort();
    }
}

// Requests are decoded using the actual RPC request type, including unary fields.
async fn streaming<Q, R>(
    req: http::Request<tonic::body::Body>,
    response: R,
) -> http::Response<tonic::body::Body>
where
    Q: prost::Message + Default + Send + 'static,
    R: prost::Message + Default + Clone + Send + Sync + 'static,
{
    let handler = tower::service_fn(move |_: tonic::Request<Q>| {
        let response = response.clone();
        async move {
            Ok::<_, tonic::Status>(tonic::Response::new(futures::stream::iter([Ok(response)])))
        }
    });
    tonic::server::Grpc::new(tonic_prost::ProstCodec::default())
        .server_streaming(handler, req)
        .await
}

async fn unary<Q, R>(
    req: http::Request<tonic::body::Body>,
    response: Result<R, tonic::Status>,
) -> http::Response<tonic::body::Body>
where
    Q: prost::Message + Default + Send + 'static,
    R: prost::Message + Default + Clone + Send + Sync + 'static,
{
    let handler = tower::service_fn(move |_: tonic::Request<Q>| {
        let response = response.clone();
        async move { response.map(tonic::Response::new) }
    });
    tonic::server::Grpc::new(tonic_prost::ProstCodec::default())
        .unary(handler, req)
        .await
}

#[derive(Clone, Default)]
struct Responses {
    x509: X509svidResponse,
    x509_bundles: X509BundlesResponse,
    jwt: JwtsvidResponse,
    jwt_bundles: JwtBundlesResponse,
    validation: Option<Result<ValidateJwtsvidResponse, tonic::Status>>,
}

async fn client(responses: Responses) -> (WorkloadApiClient, Server) {
    let service = tower::service_fn(move |req: http::Request<tonic::body::Body>| {
        let responses = responses.clone();
        async move {
            let reply = match req.uri().path() {
                "/SpiffeWorkloadAPI/FetchX509SVID" => {
                    streaming::<X509svidRequest, _>(req, responses.x509).await
                }
                "/SpiffeWorkloadAPI/FetchX509Bundles" => {
                    streaming::<X509BundlesRequest, _>(req, responses.x509_bundles).await
                }
                "/SpiffeWorkloadAPI/FetchJWTSVID" => {
                    unary::<JwtsvidRequest, _>(req, Ok(responses.jwt)).await
                }
                "/SpiffeWorkloadAPI/FetchJWTBundles" => {
                    streaming::<JwtBundlesRequest, _>(req, responses.jwt_bundles).await
                }
                "/SpiffeWorkloadAPI/ValidateJWTSVID" => {
                    unary::<ValidateJwtsvidRequest, _>(req, responses.validation.unwrap()).await
                }
                path => panic!("unexpected RPC {path}"),
            };
            Ok::<_, std::convert::Infallible>(reply)
        }
    });
    let (io_tx, io_rx) = tokio::sync::mpsc::unbounded_channel();
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
    (
        WorkloadApiClient::new_with_channel("tcp://127.0.0.1:1".parse().unwrap(), channel),
        server,
    )
}

fn missing<T>(result: Result<T, WorkloadApiError>, field: &'static str) {
    let error = result.err().expect("required field must be rejected");
    assert!(
        matches!(error, WorkloadApiError::MissingRequiredField { field: actual } if actual == field),
        "expected missing {field}"
    );
}

#[cfg(feature = "x509")]
fn x509() -> X509svidResponse {
    X509svidResponse {
        svids: vec![X509svid {
            spiffe_id: "spiffe://example.org/service".into(),
            x509_svid: include_bytes!("../../../tests/testdata/svid/x509/1-svid-chain.der")
                .to_vec()
                .into(),
            x509_svid_key: include_bytes!("../../../tests/testdata/svid/x509/1-key.der")
                .to_vec()
                .into(),
            bundle: include_bytes!("../../../tests/testdata/bundle/x509/cert1.der")
                .to_vec()
                .into(),
            hint: String::new(),
        }],
        ..Default::default()
    }
}

#[cfg(feature = "x509")]
#[tokio::test]
async fn x509_public_methods_reject_every_missing_required_field() {
    for second in [false, true] {
        for field in ["spiffe_id", "x509_svid", "x509_svid_key", "bundle"] {
            let mut response = x509();
            if second {
                response.svids.push(response.svids.first().unwrap().clone());
            }
            let entry = response.svids.last_mut().unwrap();
            match field {
                "spiffe_id" => entry.spiffe_id.clear(),
                "x509_svid" => entry.x509_svid = prost::bytes::Bytes::new(),
                "x509_svid_key" => entry.x509_svid_key = prost::bytes::Bytes::new(),
                "bundle" => entry.bundle = prost::bytes::Bytes::new(),
                _ => panic!("unexpected field"),
            }
            let field = match field {
                "spiffe_id" => "X509SVID.spiffe_id",
                "x509_svid" => "X509SVID.x509_svid",
                "x509_svid_key" => "X509SVID.x509_svid_key",
                _ => "X509SVID.bundle",
            };
            let (client, _server) = client(Responses {
                x509: response,
                ..Default::default()
            })
            .await;
            missing(client.fetch_x509_svid().await, field);
            missing(client.fetch_all_x509_svids().await, field);
            missing(client.fetch_x509_context().await, field);
            missing(
                client
                    .stream_x509_svids()
                    .await
                    .unwrap()
                    .next()
                    .await
                    .unwrap(),
                field,
            );
            missing(
                client
                    .stream_x509_contexts()
                    .await
                    .unwrap()
                    .next()
                    .await
                    .unwrap(),
                field,
            );
        }
    }
}

#[cfg(feature = "x509")]
#[tokio::test]
async fn x509_public_methods_reject_empty_required_svid_list() {
    let (client, _server) = client(Responses::default()).await;
    missing(client.fetch_x509_svid().await, "X509SVIDResponse.svids");
    missing(
        client.fetch_all_x509_svids().await,
        "X509SVIDResponse.svids",
    );
    missing(client.fetch_x509_context().await, "X509SVIDResponse.svids");
    missing(
        client
            .stream_x509_svids()
            .await
            .unwrap()
            .next()
            .await
            .unwrap(),
        "X509SVIDResponse.svids",
    );
    missing(
        client
            .stream_x509_contexts()
            .await
            .unwrap()
            .next()
            .await
            .unwrap(),
        "X509SVIDResponse.svids",
    );
}

#[cfg(feature = "x509")]
#[tokio::test]
async fn x509_public_methods_accept_valid_entries_and_optional_federation_removal() {
    for multiple in [false, true] {
        let mut response = x509();
        if multiple {
            let mut second = response.svids.first().unwrap().clone();
            second.hint = "second".into();
            response.svids.push(second);
        }
        // Wire identity is metadata; the certificate remains the identity source.
        response.svids.first_mut().unwrap().spiffe_id = "spiffe://other.example/metadata".into();
        let (client, _server) = client(Responses {
            x509: response,
            ..Default::default()
        })
        .await;
        let svid = client.fetch_x509_svid().await.unwrap();
        assert_eq!(svid.spiffe_id().to_string(), "spiffe://example.org/service");
        assert_eq!(
            client.fetch_all_x509_svids().await.unwrap().len(),
            if multiple { 2 } else { 1 }
        );
        let context = client.fetch_x509_context().await.unwrap();
        assert_eq!(context.bundle_set().len(), 1);
        client
            .stream_x509_svids()
            .await
            .unwrap()
            .next()
            .await
            .unwrap()
            .unwrap();
        client
            .stream_x509_contexts()
            .await
            .unwrap()
            .next()
            .await
            .unwrap()
            .unwrap();
    }
}

#[cfg(feature = "x509")]
#[tokio::test]
async fn x509_public_methods_reject_malformed_later_material() {
    for field in ["certificate", "key", "bundle"] {
        let mut response = x509();
        let mut second = response.svids.first().unwrap().clone();
        match field {
            "certificate" => second.x509_svid = b"invalid".to_vec().into(),
            "key" => second.x509_svid_key = b"invalid".to_vec().into(),
            _ => second.bundle = b"invalid".to_vec().into(),
        }
        response.svids.push(second);
        let (client, _server) = client(Responses {
            x509: response,
            ..Default::default()
        })
        .await;
        for error in [
            client.fetch_x509_svid().await.unwrap_err(),
            client.fetch_all_x509_svids().await.unwrap_err(),
            client.fetch_x509_context().await.unwrap_err(),
        ] {
            if field == "bundle" {
                assert!(matches!(error, WorkloadApiError::X509Bundle(_)));
            } else {
                assert!(matches!(error, WorkloadApiError::X509Svid(_)));
            }
        }
    }
}

#[cfg(feature = "x509")]
#[tokio::test]
async fn x509_bundle_public_methods_validate_required_map_and_all_entries() {
    let (client, _server) = client(Responses::default()).await;
    missing(
        client.fetch_x509_bundles().await,
        "X509BundlesResponse.bundles",
    );
    missing(
        client
            .stream_x509_bundles()
            .await
            .unwrap()
            .next()
            .await
            .unwrap(),
        "X509BundlesResponse.bundles",
    );
    for malformed in [false, true] {
        let bundle = x509().svids.remove(0).bundle;
        let response = X509BundlesResponse {
            bundles: HashMap::from([
                ("spiffe://example.org".into(), bundle.clone()),
                (
                    "spiffe://federated.example.org".into(),
                    if malformed {
                        b"invalid".to_vec().into()
                    } else {
                        bundle
                    },
                ),
            ]),
            ..Default::default()
        };
        let (client, _server) = self::client(Responses {
            x509_bundles: response,
            ..Default::default()
        })
        .await;
        let fetched = client.fetch_x509_bundles().await;
        let streamed = client
            .stream_x509_bundles()
            .await
            .unwrap()
            .next()
            .await
            .unwrap();
        for result in [fetched, streamed] {
            if malformed {
                assert!(matches!(result, Err(WorkloadApiError::X509Bundle(_))));
            } else {
                assert_eq!(result.unwrap().len(), 2);
            }
        }
    }
}

#[cfg(feature = "jwt")]
fn token() -> String {
    let fixtures: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/testdata/jwt/authority-policy.json"
    ))
    .unwrap();
    fixtures
        .get(0)
        .unwrap()
        .get("token")
        .unwrap()
        .as_str()
        .unwrap()
        .into()
}

#[cfg(feature = "jwt")]
fn jwt() -> JwtsvidResponse {
    JwtsvidResponse {
        svids: vec![Jwtsvid {
            spiffe_id: "spiffe://example.org/workload".into(),
            svid: token(),
            hint: String::new(),
        }],
    }
}

#[cfg(feature = "jwt")]
#[tokio::test]
async fn jwt_public_methods_reject_every_missing_required_field() {
    for second in [false, true] {
        for field in ["JWTSVID.spiffe_id", "JWTSVID.svid"] {
            let mut response = jwt();
            if second {
                response.svids.push(response.svids.first().unwrap().clone());
            }
            let entry = response.svids.last_mut().unwrap();
            if field == "JWTSVID.spiffe_id" {
                entry.spiffe_id.clear();
            } else {
                entry.svid.clear();
            }
            let (client, _server) = client(Responses {
                jwt: response,
                ..Default::default()
            })
            .await;
            missing(client.fetch_jwt_svid(["receiver"], None).await, field);
            missing(client.fetch_all_jwt_svids(["receiver"], None).await, field);
            missing(client.fetch_jwt_token(["receiver"], None).await, field);
            missing(
                client
                    .fetch_jwt_svid_by_hint(["receiver"], None, "second")
                    .await,
                field,
            );
        }
    }
}

#[cfg(feature = "jwt")]
#[tokio::test]
async fn jwt_public_methods_reject_empty_required_svid_list() {
    let (client, _server) = client(Responses::default()).await;
    missing(
        client.fetch_jwt_svid(["receiver"], None).await,
        "JWTSVIDResponse.svids",
    );
    missing(
        client.fetch_all_jwt_svids(["receiver"], None).await,
        "JWTSVIDResponse.svids",
    );
    missing(
        client.fetch_jwt_token(["receiver"], None).await,
        "JWTSVIDResponse.svids",
    );
}

#[cfg(feature = "jwt")]
#[tokio::test]
async fn jwt_public_methods_preserve_parse_only_selection_and_hints() {
    for multiple in [false, true] {
        let mut response = jwt();
        // A valid metadata ID need not be made equal to the parsed token subject.
        response.svids.first_mut().unwrap().spiffe_id = "spiffe://other.example/metadata".into();
        if multiple {
            let mut second = response.svids.first().unwrap().clone();
            second.hint = "second".into();
            response.svids.push(second);
        }
        let (client, _server) = client(Responses {
            jwt: response,
            ..Default::default()
        })
        .await;
        assert_eq!(
            client.fetch_jwt_token(["receiver"], None).await.unwrap(),
            token()
        );
        let expected = crate::JwtSvid::parse_insecure(&token()).unwrap();
        assert_eq!(
            client.fetch_jwt_svid(["receiver"], None).await.unwrap(),
            expected
        );
        assert_eq!(
            client
                .fetch_all_jwt_svids(["receiver"], None)
                .await
                .unwrap()
                .len(),
            if multiple { 2 } else { 1 }
        );
        if multiple {
            assert_eq!(
                client
                    .fetch_jwt_svid_by_hint(["receiver"], None, "second")
                    .await
                    .unwrap()
                    .hint(),
                Some("second")
            );
        }
    }
}

#[cfg(feature = "jwt")]
#[tokio::test]
async fn jwt_public_svid_methods_reject_malformed_later_token() {
    let mut response = jwt();
    let mut second = response.svids.first().unwrap().clone();
    second.svid = "invalid".into();
    response.svids.push(second);
    let (client, _server) = client(Responses {
        jwt: response,
        ..Default::default()
    })
    .await;
    assert!(matches!(
        client.fetch_jwt_svid(["receiver"], None).await,
        Err(WorkloadApiError::JwtSvid(_))
    ));
    assert!(matches!(
        client.fetch_all_jwt_svids(["receiver"], None).await,
        Err(WorkloadApiError::JwtSvid(_))
    ));
}

#[cfg(feature = "jwt")]
#[tokio::test]
async fn jwt_bundle_public_methods_validate_required_map_and_all_entries() {
    let (client, _server) = client(Responses::default()).await;
    missing(
        client.fetch_jwt_bundles().await,
        "JWTBundlesResponse.bundles",
    );
    missing(
        client
            .stream_jwt_bundles()
            .await
            .unwrap()
            .next()
            .await
            .unwrap(),
        "JWTBundlesResponse.bundles",
    );
    for (malformed, empty_keys) in [(false, false), (true, false), (false, true)] {
        let fixtures: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/testdata/jwt/authority-policy.json"
        ))
        .unwrap();
        let bundle: prost::bytes::Bytes = serde_json::to_vec(&serde_json::json!({
            "keys": [fixtures.get(0).unwrap().get("jwk").unwrap()]
        }))
        .unwrap()
        .into();
        let response = JwtBundlesResponse {
            bundles: HashMap::from([
                ("spiffe://example.org".into(), bundle.clone()),
                (
                    "spiffe://federated.example.org".into(),
                    if malformed {
                        b"invalid".to_vec().into()
                    } else if empty_keys {
                        // A present bundle may completely remove its authorities.
                        br#"{"keys":[]}"#.to_vec().into()
                    } else {
                        bundle
                    },
                ),
            ]),
        };
        let (client, _server) = self::client(Responses {
            jwt_bundles: response,
            ..Default::default()
        })
        .await;
        for result in [
            client.fetch_jwt_bundles().await,
            client
                .stream_jwt_bundles()
                .await
                .unwrap()
                .next()
                .await
                .unwrap(),
        ] {
            if malformed {
                assert!(matches!(result, Err(WorkloadApiError::JwtBundle(_))));
            } else {
                assert_eq!(result.unwrap().len(), 2);
            }
        }
    }
}

#[cfg(feature = "jwt")]
fn validation() -> ValidateJwtsvidResponse {
    use prost_types::{value::Kind, Struct, Value};
    ValidateJwtsvidResponse {
        spiffe_id: "spiffe://example.org/workload".into(),
        claims: Some(Struct {
            fields: [
                (
                    "sub".into(),
                    Value {
                        kind: Some(Kind::StringValue("spiffe://example.org/workload".into())),
                    },
                ),
                (
                    "aud".into(),
                    Value {
                        kind: Some(Kind::StringValue("receiver".into())),
                    },
                ),
                (
                    "exp".into(),
                    Value {
                        kind: Some(Kind::NumberValue(4_294_967_295.0)),
                    },
                ),
            ]
            .into(),
        }),
    }
}

#[cfg(feature = "jwt")]
#[tokio::test]
async fn validate_jwt_public_method_rejects_missing_required_response_fields() {
    for field in [
        "ValidateJWTSVIDResponse.spiffe_id",
        "ValidateJWTSVIDResponse.claims",
        "ValidateJWTSVIDResponse.claims.sub",
        "ValidateJWTSVIDResponse.claims.aud",
        "ValidateJWTSVIDResponse.claims.exp",
    ] {
        let mut response = validation();
        match field {
            "ValidateJWTSVIDResponse.spiffe_id" => response.spiffe_id.clear(),
            "ValidateJWTSVIDResponse.claims" => response.claims = None,
            _ => {
                response
                    .claims
                    .as_mut()
                    .unwrap()
                    .fields
                    .remove(field.rsplit('.').next().unwrap());
            }
        }
        let (client, _server) = client(Responses {
            validation: Some(Ok(response)),
            ..Default::default()
        })
        .await;
        missing(client.validate_jwt_token("receiver", &token()).await, field);
    }
    let (client, _server) = client(Responses {
        validation: Some(Ok(ValidateJwtsvidResponse::default())),
        ..Default::default()
    })
    .await;
    missing(
        client.validate_jwt_token("receiver", &token()).await,
        "ValidateJWTSVIDResponse.spiffe_id",
    );
}

#[cfg(feature = "jwt")]
#[tokio::test]
async fn validate_jwt_public_method_preserves_agent_validation_and_optional_claims() {
    use prost_types::{value::Kind, ListValue, Struct, Value};
    for audience in [
        Kind::StringValue("receiver".into()),
        Kind::ListValue(ListValue {
            values: vec![Value {
                kind: Some(Kind::StringValue("receiver".into())),
            }],
        }),
    ] {
        let mut response = validation();
        let fields = &mut response.claims.as_mut().unwrap().fields;
        fields.get_mut("aud").unwrap().kind = Some(audience);
        fields.insert(
            "optional".into(),
            Value {
                kind: Some(Kind::StructValue(Struct::default())),
            },
        );
        // No client clock check or response/token equality policy is introduced.
        fields.get_mut("exp").unwrap().kind = Some(Kind::NumberValue(-0.5));
        let (client, _server) = client(Responses {
            validation: Some(Ok(response)),
            ..Default::default()
        })
        .await;
        assert_eq!(
            client
                .validate_jwt_token("receiver", &token())
                .await
                .unwrap(),
            crate::JwtSvid::parse_insecure(&token()).unwrap()
        );
    }
    let (client, _server) = client(Responses {
        validation: Some(Err(tonic::Status::permission_denied("denied"))),
        ..Default::default()
    })
    .await;
    assert!(
        matches!(client.validate_jwt_token("receiver", &token()).await, Err(WorkloadApiError::PermissionDenied(message)) if message == "denied")
    );
}

#[cfg(feature = "jwt")]
#[tokio::test]
async fn validate_jwt_public_method_rejects_malformed_required_claims() {
    use prost_types::{value::Kind, ListValue, Struct, Value};
    for (name, kind) in [
        ("sub", Kind::StringValue(String::new())),
        ("sub", Kind::StringValue("invalid SPIFFE ID".into())),
        ("sub", Kind::NumberValue(1.0)),
        ("aud", Kind::ListValue(ListValue::default())),
        (
            "aud",
            Kind::ListValue(ListValue {
                values: vec![Value {
                    kind: Some(Kind::NumberValue(1.0)),
                }],
            }),
        ),
        ("aud", Kind::StructValue(Struct::default())),
        ("aud", Kind::NullValue(0)),
        ("exp", Kind::StringValue("4294967295".into())),
        ("exp", Kind::NumberValue(f64::NAN)),
        ("exp", Kind::NumberValue(f64::INFINITY)),
    ] {
        let mut response = validation();
        response
            .claims
            .as_mut()
            .unwrap()
            .fields
            .get_mut(name)
            .unwrap()
            .kind = Some(kind);
        let field = match name {
            "sub" => "ValidateJWTSVIDResponse.claims.sub",
            "aud" => "ValidateJWTSVIDResponse.claims.aud",
            _ => "ValidateJWTSVIDResponse.claims.exp",
        };
        let (client, _server) = client(Responses {
            validation: Some(Ok(response)),
            ..Default::default()
        })
        .await;
        assert!(
            matches!(client.validate_jwt_token("receiver", &token()).await, Err(WorkloadApiError::InvalidResponseField { field: actual }) if actual == field)
        );
    }
    let mut response = validation();
    response.claims = Some(Struct::default());
    let (client, _server) = client(Responses {
        validation: Some(Ok(response)),
        ..Default::default()
    })
    .await;
    missing(
        client.validate_jwt_token("receiver", &token()).await,
        "ValidateJWTSVIDResponse.claims.sub",
    );
}
