//! Delegated bundle response validation through public clients over tonic/HTTP2.

#![expect(unused_crate_dependencies, reason = "used in the library target")]

#[cfg(test)]
mod tests {
    use futures::StreamExt as _;
    use prost::bytes::Bytes;
    use spiffe::{JwtBundleSet, TrustDomain, X509BundleSet};
    use spire_api::pb::spire::api::agent::delegatedidentity::v1::{
        SubscribeToJwtBundlesRequest, SubscribeToX509BundlesRequest,
    };
    use spire_api::{DelegatedIdentityClient, DelegatedIdentityError};
    use std::convert::Infallible;
    use std::task::{Context, Poll};
    use tonic::codegen::{http, BoxFuture, BoxStream, Service};

    const CA1: &[u8] = include_bytes!("../../spiffe/tests/testdata/bundle/x509/cert1.der");
    const CA2: &[u8] = include_bytes!("../../spiffe/tests/testdata/bundle/x509/cert2.der");

    // Real P-256 public keys from the core authority-policy fixture and JwtBundle Rustdoc.
    fn jwks(kid: &str, second_key: bool) -> Bytes {
        let (x, y) = if second_key {
            (
                "ngLYQnlfF6GsojUwqtcEE3WgTNG2RUlsGhK73RNEl5k",
                "tKbiDSUSsQ3F1P7wteeHNXIcU-cx6CgSbroeQrQHTLM",
            )
        } else {
            (
                "pf-F3qt3WiBQ2hPjVIp0W8C-ltc7VGCJqW-0sJgoKTI",
                "bsqDObxnMnAkXVbmLLlxinbSRyaLNL-28UWmN5rlg44",
            )
        };
        format!(r#"{{"keys":[{{"kty":"EC","crv":"P-256","kid":"{kid}","x":"{x}","y":"{y}"}}]}}"#)
            .into()
    }

    // Both response maps use field 1 with string keys and byte values. Repeated
    // entries have the same protobuf encoding as a map, but let tests control
    // wire order. The public client decodes the real generated response HashMap.
    #[derive(Clone, PartialEq, prost::Message)]
    struct WireBundles {
        #[prost(message, repeated, tag = "1")]
        entries: Vec<WireEntry>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    struct WireEntry {
        #[prost(string, tag = "1")]
        key: String,
        #[prost(bytes = "bytes", tag = "2")]
        value: Bytes,
    }

    fn response(entries: &[(&str, Bytes)]) -> WireBundles {
        WireBundles {
            entries: entries
                .iter()
                .map(|(key, value)| WireEntry {
                    key: (*key).to_owned(),
                    value: value.clone(),
                })
                .collect(),
        }
    }

    #[derive(Clone)]
    struct Responses(Vec<WireBundles>);

    impl<Q> tonic::server::ServerStreamingService<Q> for Responses {
        type Response = WireBundles;
        type ResponseStream = BoxStream<WireBundles>;
        type Future = BoxFuture<tonic::Response<Self::ResponseStream>, tonic::Status>;

        fn call(&mut self, _request: tonic::Request<Q>) -> Self::Future {
            let stream = futures::stream::iter(self.0.clone().into_iter().map(Ok));
            let stream: BoxStream<_> = Box::pin(stream);
            Box::pin(async move { Ok(tonic::Response::new(stream)) })
        }
    }

    impl Service<http::Request<tonic::body::Body>> for Responses {
        type Response = http::Response<tonic::body::Body>;
        type Error = Infallible;
        type Future = BoxFuture<Self::Response, Self::Error>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: http::Request<tonic::body::Body>) -> Self::Future {
            let responses = self.clone();
            Box::pin(async move {
                let reply = match req.uri().path() {
                    "/spire.api.agent.delegatedidentity.v1.DelegatedIdentity/SubscribeToX509Bundles" => {
                        tonic::server::Grpc::new(tonic_prost::ProstCodec::<WireBundles, SubscribeToX509BundlesRequest>::default())
                            .server_streaming(responses, req)
                            .await
                    }
                    "/spire.api.agent.delegatedidentity.v1.DelegatedIdentity/SubscribeToJWTBundles" => {
                        tonic::server::Grpc::new(tonic_prost::ProstCodec::<WireBundles, SubscribeToJwtBundlesRequest>::default())
                            .server_streaming(responses, req)
                            .await
                    }
                    path => panic!("unexpected RPC {path}"),
                };
                Ok(reply)
            })
        }
    }

    struct Server(tokio::task::JoinHandle<()>);

    impl Drop for Server {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

    async fn client(updates: Vec<WireBundles>) -> (DelegatedIdentityClient, Server) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let incoming = futures::stream::unfold(listener, async |listener| {
            let result = listener.accept().await.map(|(stream, _)| stream);
            Some((result, listener))
        });
        let server = Server(tokio::spawn(async move {
            tonic::transport::Server::builder()
                .serve_with_incoming(Responses(updates), incoming)
                .await
                .unwrap();
        }));
        let channel = tonic::transport::Endpoint::from_shared(format!("http://{address}"))
            .unwrap()
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(5))
            .connect()
            .await
            .unwrap();
        (DelegatedIdentityClient::new(channel), server)
    }

    async fn x509_results(
        entries: &[(&str, Bytes)],
    ) -> [Result<X509BundleSet, DelegatedIdentityError>; 2] {
        let (client, _server) = client(vec![response(entries)]).await;
        let fetched = client.fetch_x509_bundles().await;
        let mut stream = client.stream_x509_bundles().await.unwrap();
        let streamed = stream.next().await.unwrap();
        assert!(stream.next().await.is_none());
        [fetched, streamed]
    }

    async fn jwt_results(
        entries: &[(&str, Bytes)],
    ) -> [Result<JwtBundleSet, DelegatedIdentityError>; 2] {
        let (client, _server) = client(vec![response(entries)]).await;
        let fetched = client.fetch_jwt_bundles().await;
        let mut stream = client.stream_jwt_bundles().await.unwrap();
        let streamed = stream.next().await.unwrap();
        assert!(stream.next().await.is_none());
        [fetched, streamed]
    }

    fn invalid_key<T: std::fmt::Debug>(result: Result<T, DelegatedIdentityError>, key: &str) {
        let error = result.expect_err("invalid wire key must reject the whole response");
        assert_eq!(
            error.to_string(),
            format!("invalid delegated bundle key {key:?}")
        );
        assert!(
            matches!(error, DelegatedIdentityError::InvalidBundleKey { key: actual } if actual == key)
        );
    }

    fn duplicate<T: std::fmt::Debug>(result: Result<T, DelegatedIdentityError>) {
        let error = result.expect_err("canonical collision must reject the whole response");
        assert_eq!(
            error.to_string(),
            "duplicate delegated bundle trust domain example.org"
        );
        assert!(
            matches!(error, DelegatedIdentityError::DuplicateTrustDomain { trust_domain } if trust_domain.as_str() == "example.org")
        );
    }

    #[tokio::test]
    async fn x509_valid_bare_and_root_domains() {
        let longest_domain = "a".repeat(255);
        let longest_root = format!("spiffe://{longest_domain}");
        for keys in [
            vec!["example.org"],
            vec!["EXAMPLE.ORG"],
            vec!["spiffe://example.org"],
            vec!["spiffe://EXAMPLE.ORG"],
            vec!["SPIFFE://EXAMPLE.ORG"],
            vec!["example.org", "federated.example.org"],
            vec!["spiffe://example.org", "spiffe://federated.example.org"],
            vec!["example.org", "spiffe://federated.example.org"],
            vec!["local_1.test", "other-domain.test", "127.0.0.1"],
            vec![longest_domain.as_str()],
            vec![longest_root.as_str()],
        ] {
            let entries: Vec<_> = keys
                .iter()
                .enumerate()
                .map(|(index, key)| (*key, Bytes::from_static(if index == 0 { CA1 } else { CA2 })))
                .collect();
            for result in x509_results(&entries).await {
                let bundles = result.unwrap();
                assert_eq!(bundles.len(), entries.len());
                for (index, key) in keys.iter().enumerate() {
                    let bundle = bundles.get(&TrustDomain::new(key).unwrap()).unwrap();
                    assert_eq!(bundle.authorities().len(), 1);
                    assert_eq!(
                        bundle.authorities().first().unwrap().as_ref(),
                        if index == 0 { CA1 } else { CA2 }
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn spire_1_15_2_x509_root_uri_compatibility() {
        // SPIRE 1.15.2 service.go:314 emits td.IDString() for X.509 bundles.
        for result in x509_results(&[("spiffe://example.org", Bytes::from_static(CA1))]).await {
            let bundles = result.expect("SPIRE 1.15.2 root URI keys must remain usable");
            assert_eq!(bundles.len(), 1);
            let bundle = bundles
                .get(&TrustDomain::new("example.org").unwrap())
                .unwrap();
            assert_eq!(bundle.authorities().len(), 1);
            assert_eq!(bundle.authorities().first().unwrap().as_ref(), CA1);
        }
    }

    #[tokio::test]
    async fn jwt_valid_root_domains_and_authorities() {
        let longest_root = format!("spiffe://{}", "a".repeat(255));
        for keys in [
            vec!["spiffe://example.org"],
            vec!["SPIFFE://EXAMPLE.ORG"],
            vec!["spiffe://example.org", "spiffe://federated.example.org"],
            vec![
                "spiffe://local_1.test",
                "spiffe://other-domain.test",
                "spiffe://127.0.0.1",
            ],
            vec![longest_root.as_str()],
        ] {
            let entries: Vec<_> = keys
                .iter()
                .enumerate()
                .map(|(index, key)| {
                    (
                        *key,
                        jwks(if index == 0 { "first" } else { "second" }, index != 0),
                    )
                })
                .collect();
            for result in jwt_results(&entries).await {
                let bundles = result.unwrap();
                assert_eq!(bundles.len(), entries.len());
                for (index, key) in keys.iter().enumerate() {
                    let bundle = bundles.get(&TrustDomain::new(key).unwrap()).unwrap();
                    assert_eq!(bundle.jwt_authorities().count(), 1);
                    let kid = if index == 0 { "first" } else { "second" };
                    assert_eq!(bundle.find_jwt_authority(kid).unwrap().key_id(), kid);
                }
            }
        }
    }

    #[tokio::test]
    async fn x509_invalid_keys_reject_whole_response_in_both_wire_orders() {
        let too_long = "a".repeat(256);
        let too_long_root = format!("spiffe://{too_long}");
        for key in [
            "",
            "spiffe://",
            "spiffe:/example.org",
            "spiffe:example.org",
            "spiffe:///example.org",
            "https://example.org",
            "https:example.org",
            "spiffe://example.org/",
            "spiffe://example.org/workload",
            "spiffe://example.org/.",
            "spiffe://example.org/..",
            "spiffe://example.org//",
            "spiffe://example.org/%2f",
            "spiffe://example.org/bad path",
            "spiffe://example.org/path?query",
            "spiffe://example.org/path#fragment",
            "spiffe://example.org?query",
            "spiffe://example.org#fragment",
            "spiffe://example.org:443",
            "spiffe://user@example.org",
            "spiffe://bad%20domain",
            "spiffe://bad:domain",
            "example.org/",
            "example.org/workload",
            "bad:domain",
            "example.org:443",
            "user@example.org",
            "bad%20domain",
            "bad domain",
            "nonascii\u{e9}",
            "example.org?query",
            "example.org#fragment",
            too_long.as_str(),
            too_long_root.as_str(),
        ] {
            let mut entries = vec![
                ("valid.test", Bytes::from_static(CA1)),
                (key, Bytes::from_static(CA2)),
            ];
            for _ in 0..2 {
                for result in x509_results(&entries).await {
                    invalid_key(result, key);
                }
                entries.reverse();
            }
        }
    }

    #[tokio::test]
    async fn jwt_invalid_keys_reject_whole_response_in_both_wire_orders() {
        let too_long = format!("spiffe://{}", "a".repeat(256));
        for key in [
            "",
            "example.org",
            "spiffe://",
            "https://example.org",
            "spiffe:/example.org",
            "spiffe://example.org/",
            "spiffe://example.org/workload",
            "spiffe://example.org/.",
            "spiffe://example.org/..",
            "spiffe://example.org//",
            "spiffe://example.org/%2f",
            "spiffe://example.org/bad path",
            "spiffe://example.org/path?query",
            "spiffe://example.org/path#fragment",
            "spiffe://example.org?query",
            "spiffe://example.org#fragment",
            "spiffe://bad:domain",
            "spiffe://user@example.org",
            "spiffe://bad%20domain",
            too_long.as_str(),
        ] {
            let mut entries = vec![
                ("spiffe://valid.test", jwks("first", false)),
                (key, jwks("second", true)),
            ];
            for _ in 0..2 {
                for result in jwt_results(&entries).await {
                    invalid_key(result, key);
                }
                entries.reverse();
            }
        }
    }

    #[tokio::test]
    async fn x509_collisions_reject_identical_and_conflicting_authorities() {
        for (first, alias) in [
            ("example.org", "EXAMPLE.ORG"),
            ("spiffe://example.org", "spiffe://EXAMPLE.ORG"),
            ("example.org", "spiffe://example.org"),
            ("EXAMPLE.ORG", "SPIFFE://example.org"),
        ] {
            for other in [CA1, CA2, &[]] {
                let mut entries = vec![
                    (first, Bytes::from_static(CA1)),
                    (alias, Bytes::copy_from_slice(other)),
                    ("spiffe://federated.test", Bytes::from_static(CA2)),
                ];
                for _ in 0..2 {
                    for result in x509_results(&entries).await {
                        duplicate(result);
                    }
                    entries.reverse();
                }
            }
        }
    }

    #[tokio::test]
    async fn jwt_collisions_reject_identical_keys_different_keys_and_different_kids() {
        for alias in [
            "spiffe://EXAMPLE.ORG",
            "SPIFFE://example.org",
            "SPIFFE://EXAMPLE.ORG",
        ] {
            for other in [
                jwks("first", false),
                jwks("first", true),
                jwks("second", true),
                Bytes::from_static(br#"{"keys":[]}"#),
            ] {
                let mut entries = vec![
                    ("spiffe://example.org", jwks("first", false)),
                    (alias, other),
                    ("spiffe://federated.test", jwks("third", true)),
                ];
                for _ in 0..2 {
                    for result in jwt_results(&entries).await {
                        duplicate(result);
                    }
                    entries.reverse();
                }
            }
        }
    }

    #[tokio::test]
    async fn malformed_aliases_are_invalid_keys_not_duplicates() {
        for key in [
            "spiffe://example.org/",
            "spiffe://example.org/workload",
            "spiffe://example.org/%invalid",
            "spiffe://example.org?query",
            "spiffe://example.org#fragment",
        ] {
            for result in x509_results(&[
                ("example.org", Bytes::from_static(CA1)),
                (key, Bytes::from_static(CA1)),
            ])
            .await
            {
                invalid_key(result, key);
            }
        }
        for key in [
            "example.org",
            "spiffe://example.org/",
            "spiffe://example.org/workload",
            "spiffe://example.org/%invalid",
        ] {
            for result in jwt_results(&[
                ("spiffe://example.org", jwks("first", false)),
                (key, jwks("first", false)),
            ])
            .await
            {
                invalid_key(result, key);
            }
        }
    }

    #[tokio::test]
    async fn empty_maps_and_empty_authority_sets_remain_accepted() {
        for result in x509_results(&[]).await {
            assert!(result.unwrap().is_empty());
        }
        for result in jwt_results(&[]).await {
            assert!(result.unwrap().is_empty());
        }
        for key in ["example.org", "spiffe://example.org"] {
            for result in x509_results(&[(key, Bytes::new())]).await {
                let bundles = result.unwrap();
                assert_eq!(bundles.len(), 1);
                assert_eq!(
                    bundles
                        .get(&TrustDomain::new("example.org").unwrap())
                        .unwrap()
                        .authorities(),
                    []
                );
            }
        }
        for result in jwt_results(&[(
            "spiffe://example.org",
            Bytes::from_static(br#"{"keys":[]}"#),
        )])
        .await
        {
            let bundles = result.unwrap();
            assert_eq!(bundles.len(), 1);
            assert_eq!(
                bundles
                    .get(&TrustDomain::new("example.org").unwrap())
                    .unwrap()
                    .jwt_authorities()
                    .count(),
                0
            );
        }
    }

    #[tokio::test]
    async fn invalid_bundle_material_rejects_whole_response() {
        let mut x509 = vec![
            ("valid.test", Bytes::from_static(CA1)),
            ("other.test", Bytes::from_static(b"invalid")),
        ];
        let mut jwt = vec![
            ("spiffe://valid.test", jwks("first", false)),
            ("spiffe://other.test", Bytes::new()),
        ];
        for _ in 0..2 {
            for result in x509_results(&x509).await {
                assert!(matches!(result, Err(DelegatedIdentityError::X509Bundle(_))));
            }
            for result in jwt_results(&jwt).await {
                assert!(matches!(result, Err(DelegatedIdentityError::JwtBundle(_))));
            }
            x509.reverse();
            jwt.reverse();
        }
    }

    #[tokio::test]
    async fn x509_stream_validates_each_update_and_preserves_recovery() {
        let valid = response(&[("example.org", Bytes::from_static(CA1))]);
        let invalid = response(&[("spiffe://example.org/workload", Bytes::from_static(CA1))]);
        let ambiguous = response(&[
            ("example.org", Bytes::from_static(CA1)),
            ("spiffe://example.org", Bytes::from_static(CA2)),
        ]);
        let recovered = response(&[("spiffe://example.org", Bytes::from_static(CA2))]);
        let (client, _server) = client(vec![valid, invalid, ambiguous, recovered]).await;
        let mut stream = client.stream_x509_bundles().await.unwrap();
        assert_eq!(stream.next().await.unwrap().unwrap().len(), 1);
        invalid_key(
            stream.next().await.unwrap(),
            "spiffe://example.org/workload",
        );
        duplicate(stream.next().await.unwrap());
        let bundles = stream.next().await.unwrap().unwrap();
        assert_eq!(bundles.len(), 1);
        let bundle = bundles
            .get(&TrustDomain::new("example.org").unwrap())
            .unwrap();
        assert_eq!(bundle.authorities().first().unwrap().as_ref(), CA2);
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn jwt_stream_validates_each_update_and_preserves_recovery() {
        let valid = response(&[("spiffe://example.org", jwks("first", false))]);
        let invalid = response(&[("spiffe://example.org/workload", jwks("first", false))]);
        let ambiguous = response(&[
            ("spiffe://example.org", jwks("first", false)),
            ("SPIFFE://EXAMPLE.ORG", jwks("second", true)),
        ]);
        let (client, _server) = client(vec![valid.clone(), invalid, ambiguous, valid]).await;
        let mut stream = client.stream_jwt_bundles().await.unwrap();
        assert_eq!(stream.next().await.unwrap().unwrap().len(), 1);
        invalid_key(
            stream.next().await.unwrap(),
            "spiffe://example.org/workload",
        );
        duplicate(stream.next().await.unwrap());
        assert_eq!(stream.next().await.unwrap().unwrap().len(), 1);
        assert!(stream.next().await.is_none());
    }
}
