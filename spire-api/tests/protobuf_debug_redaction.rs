//! Public-consumer regressions for SPIRE protobuf credential.

#![expect(unused_crate_dependencies, reason = "used in the library target")]

#[cfg(test)]
mod tests {
    use prost::{bytes::Bytes, Message};
    use spire_api::pb::spire::api::{agent::delegatedidentity::v1 as delegated, types};
    use std::collections::{BTreeMap, HashMap};
    use std::fmt::Debug;

    const ASCII_KEY: &[u8] = b"RS023_SYNTHETIC_ASCII_KEY_ONLY";
    const BINARY_KEY: &[u8] = b"\0\x01\x1f\x7f\x80\xfe\xffRS023_BINARY_KEY_ONLY";
    const JWT: &str = "RS023_HEADER_ONLY.RS023_PAYLOAD_ONLY.RS023_SIGNATURE_ONLY";
    const SECOND_JWT: &str = "RS023_SECOND_HEADER.RS023_SECOND_PAYLOAD.RS023_SECOND_SIGNATURE";
    const ESCAPED_JWT: &str =
        "RS023_ESCAPED_HEADER\".RS023_ESCAPED_PAYLOAD\n.RS023_ESCAPED_SIGNATURE\\\u{e9}";
    const CERT: &[u8] = b"RS023_PUBLIC_CERTIFICATE";

    fn identity(path: &str) -> types::Spiffeid {
        types::Spiffeid {
            trust_domain: "rs023.example".into(),
            path: path.into(),
        }
    }

    fn x509(key: &'static [u8], path: &str) -> delegated::X509svidWithKey {
        delegated::X509svidWithKey {
            x509_svid: Some(types::X509svid {
                cert_chain: vec![Bytes::from_static(CERT)],
                id: Some(identity(path)),
                expires_at: 2_000_000_000,
                hint: format!("public-x509-hint{path}"),
            }),
            x509_svid_key: Bytes::from_static(key),
        }
    }

    fn jwt(token: &str, path: &str) -> types::Jwtsvid {
        types::Jwtsvid {
            token: token.into(),
            id: Some(identity(path)),
            expires_at: 2_000_000_000,
            issued_at: 1_900_000_000,
            hint: format!("public-jwt-hint{path}"),
        }
    }

    #[derive(Debug)]
    struct ApplicationEnvelope<T> {
        #[expect(dead_code, reason = "exercises a downstream derived Debug field")]
        credential: T,
    }

    fn formats<T: Debug>(value: &T) -> [String; 2] {
        [format!("{value:?}"), format!("{value:#?}")]
    }

    fn contextual_formats<T: Debug>(value: &T) -> Vec<(&'static str, String)> {
        let contexts = [
            ("direct", formats(value)),
            ("Vec", formats(&vec![value])),
            ("Option", formats(&Some(value))),
            ("Result", formats(&Ok::<_, ()>(value))),
            (
                "BTreeMap",
                formats(&BTreeMap::from([("credential", value)])),
            ),
            ("HashMap", formats(&HashMap::from([("credential", value)]))),
            ("tonic::Response", formats(&tonic::Response::new(value))),
            (
                "Vec<tonic::Response>",
                formats(&vec![tonic::Response::new(value)]),
            ),
            (
                "application derive(Debug)",
                formats(&ApplicationEnvelope { credential: value }),
            ),
        ];
        contexts
            .into_iter()
            .flat_map(|(context, outputs)| outputs.map(|output| (context, output)))
            .collect()
    }

    fn without_whitespace(value: &str) -> String {
        value.chars().filter(|c| !c.is_whitespace()).collect()
    }

    fn assert_secrets_absent(output: &str, context: &str) {
        let normalized = without_whitespace(output);
        for key in [ASCII_KEY, BINARY_KEY] {
            // Cover Bytes' escaped byte strings and equivalent decimal byte arrays,
            // including pretty arrays with indentation and line breaks.
            for representation in formats(&Bytes::from_static(key))
                .into_iter()
                .chain(formats(&key))
            {
                assert!(
                    !normalized.contains(&without_whitespace(&representation)),
                    "{context}: private-key representation disclosed"
                );
            }
        }
        for fragment in ["ASCII_KEY_ONLY", "RS023_BINARY_KEY_ONLY", "\\x80\\xfe\\xff"] {
            assert!(
                !output.contains(fragment),
                "{context}: key fragment disclosed"
            );
        }
        for token in [JWT, SECOND_JWT, ESCAPED_JWT] {
            assert!(
                !output.contains(token),
                "{context}: complete token disclosed"
            );
            for segment in token.split('.') {
                assert!(
                    !output.contains(segment) && !output.contains(&format!("{segment:?}")),
                    "{context}: token segment disclosed"
                );
                // Also check the recognizable prefix when quotes/newlines are escaped.
                let prefix = segment.split(['"', '\n', '\\']).next().unwrap_or(segment);
                assert!(
                    !output.contains(prefix),
                    "{context}: token fragment disclosed"
                );
            }
        }
    }

    fn assert_safe<T: Debug>(value: &T, visible: &[&str], label: &str, lengths: &[usize]) {
        for (context, output) in contextual_formats(value) {
            assert_secrets_absent(&output, context);
            for text in visible {
                assert!(output.contains(text), "{context}: missing metadata {text}");
            }
            let normalized = without_whitespace(&output);
            assert_eq!(
                normalized.matches(&format!("{label}{{")).count(),
                lengths.len(),
                "{context}: missing redaction placeholders"
            );
            for len in lengths {
                assert!(
                    normalized.contains(&format!("{label}{{len:{len}}}"))
                        || normalized.contains(&format!("{label}{{len:{len},}}")),
                    "{context}: missing redacted byte length {len}"
                );
            }
        }
    }

    #[test]
    fn x509_debug_redacts_ascii_binary_and_empty_keys_in_every_context() {
        for key in [ASCII_KEY, BINARY_KEY, b"".as_slice()] {
            assert_safe(
                &x509(key, "/first"),
                &[
                    "X509svidWithKey",
                    "x509_svid_key",
                    "RS023_PUBLIC_CERTIFICATE",
                    "rs023.example",
                    "/first",
                    "2000000000",
                    "public-x509-hint/first",
                ],
                "PrivateKey",
                &[key.len()],
            );
            assert_safe(
                &delegated::X509svidWithKey {
                    x509_svid: None,
                    x509_svid_key: Bytes::from_static(key),
                },
                &["X509svidWithKey", "x509_svid", "None", "x509_svid_key"],
                "PrivateKey",
                &[key.len()],
            );
        }
    }

    #[test]
    fn jwt_debug_redacts_complete_tokens_segments_and_escaped_values_in_every_context() {
        for token in [JWT, SECOND_JWT, ESCAPED_JWT, ""] {
            assert_safe(
                &jwt(token, "/first"),
                &[
                    "Jwtsvid",
                    "token",
                    "rs023.example",
                    "/first",
                    "2000000000",
                    "1900000000",
                    "public-jwt-hint/first",
                ],
                "Token",
                &[token.len()],
            );
            let mut without_id = jwt(token, "/first");
            without_id.id = None;
            assert_safe(
                &without_id,
                &[
                    "Jwtsvid",
                    "id",
                    "None",
                    "2000000000",
                    "1900000000",
                    "public-jwt-hint/first",
                ],
                "Token",
                &[token.len()],
            );
        }
    }

    #[test]
    fn nested_responses_redact_every_credential_including_nonfirst_entries() {
        for key in [ASCII_KEY, BINARY_KEY] {
            assert_safe(
                &delegated::SubscribeToX509sviDsResponse {
                    x509_svids: vec![x509(key, "/first")],
                    federates_with: vec!["federated.example".into()],
                },
                &[
                    "SubscribeToX509sviDsResponse",
                    "federated.example",
                    "public-x509-hint/first",
                ],
                "PrivateKey",
                &[key.len()],
            );
        }
        assert_safe(
            &delegated::SubscribeToX509sviDsResponse {
                x509_svids: vec![x509(ASCII_KEY, "/first"), x509(BINARY_KEY, "/second")],
                federates_with: vec!["federated.example".into()],
            },
            &[
                "SubscribeToX509sviDsResponse",
                "federated.example",
                "RS023_PUBLIC_CERTIFICATE",
                "rs023.example",
                "2000000000",
                "public-x509-hint/first",
                "public-x509-hint/second",
            ],
            "PrivateKey",
            &[ASCII_KEY.len(), BINARY_KEY.len()],
        );
        for tokens in [vec![JWT], vec![JWT, SECOND_JWT, ESCAPED_JWT]] {
            let svids = tokens
                .iter()
                .enumerate()
                .map(|(i, token)| jwt(token, &format!("/entry-{i}")))
                .collect();
            let response = delegated::FetchJwtsviDsResponse { svids };
            let hints: Vec<String> = (0..tokens.len())
                .map(|i| format!("public-jwt-hint/entry-{i}"))
                .collect();
            let mut visible = vec![
                "FetchJwtsviDsResponse",
                "rs023.example",
                "2000000000",
                "1900000000",
            ];
            visible.extend(hints.iter().map(String::as_str));
            let lengths: Vec<usize> = tokens.iter().map(|token| token.len()).collect();
            assert_safe(&response, &visible, "Token", &lengths);
        }
    }

    #[test]
    fn default_credentials_and_empty_responses_keep_debug_available() {
        assert_safe(
            &delegated::X509svidWithKey::default(),
            &["X509svidWithKey", "x509_svid", "None", "x509_svid_key"],
            "PrivateKey",
            &[0],
        );
        assert_safe(
            &types::Jwtsvid::default(),
            &[
                "Jwtsvid",
                "token",
                "None",
                "expires_at",
                "issued_at",
                "hint",
            ],
            "Token",
            &[0],
        );
        assert_safe(
            &delegated::SubscribeToX509sviDsResponse::default(),
            &[
                "SubscribeToX509sviDsResponse",
                "x509_svids",
                "federates_with",
            ],
            "PrivateKey",
            &[],
        );
        assert_safe(
            &delegated::FetchJwtsviDsResponse::default(),
            &["FetchJwtsviDsResponse", "svids"],
            "Token",
            &[],
        );
        assert_safe(
            &delegated::SubscribeToX509sviDsResponse {
                x509_svids: vec![delegated::X509svidWithKey::default()],
                federates_with: Vec::new(),
            },
            &["SubscribeToX509sviDsResponse", "None"],
            "PrivateKey",
            &[0],
        );
        assert_safe(
            &delegated::FetchJwtsviDsResponse {
                svids: vec![types::Jwtsvid::default()],
            },
            &["FetchJwtsviDsResponse", "None"],
            "Token",
            &[0],
        );
    }

    fn assert_debug<T: Debug>() {}

    #[test]
    fn every_public_generated_message_retains_debug() {
        assert_debug::<delegated::X509svidWithKey>();
        assert_debug::<delegated::SubscribeToX509sviDsRequest>();
        assert_debug::<delegated::SubscribeToX509sviDsResponse>();
        assert_debug::<delegated::SubscribeToX509BundlesRequest>();
        assert_debug::<delegated::SubscribeToX509BundlesResponse>();
        assert_debug::<delegated::FetchJwtsviDsRequest>();
        assert_debug::<delegated::FetchJwtsviDsResponse>();
        assert_debug::<delegated::SubscribeToJwtBundlesRequest>();
        assert_debug::<delegated::SubscribeToJwtBundlesResponse>();
        assert_debug::<types::Selector>();
        assert_debug::<types::SelectorMatch>();
        assert_debug::<types::Spiffeid>();
        assert_debug::<types::X509svid>();
        assert_debug::<types::Jwtsvid>();
        assert_debug::<types::selector_match::MatchBehavior>();
        assert_debug::<
            delegated::delegated_identity_client::DelegatedIdentityClient<
                tonic::transport::Channel,
            >,
        >();
    }

    #[test]
    fn generated_debug_suppression_targets_only_the_two_credential_messages() {
        let sources = [
            include_str!("../src/pb/spire.api.agent.delegatedidentity.v1.rs"),
            include_str!("../src/pb/spire.api.types.rs"),
        ];
        let suppressed: Vec<&str> = sources
            .iter()
            .flat_map(|source| source.split("#[prost(skip_debug)]").skip(1))
            .map(|tail| {
                tail.lines()
                    .find_map(|line| line.strip_prefix("pub struct "))
                    .and_then(|declaration| declaration.split_whitespace().next())
                    .expect("suppression precedes a generated message")
            })
            .collect();
        assert_eq!(suppressed, ["X509svidWithKey", "Jwtsvid"]);
    }

    #[test]
    fn nonsecret_messages_keep_certificate_bundle_and_request_metadata_visible() {
        let certificate = x509(ASCII_KEY, "/public")
            .x509_svid
            .expect("fixture certificate");
        let selector = types::Selector {
            r#type: "unix".into(),
            value: "uid:1234".into(),
        };
        let controls = [
            (
                formats(&certificate),
                vec![
                    "RS023_PUBLIC_CERTIFICATE",
                    "rs023.example",
                    "/public",
                    "2000000000",
                    "public-x509-hint/public",
                ],
            ),
            (
                formats(&delegated::SubscribeToX509BundlesResponse {
                    ca_certificates: HashMap::from([(
                        "rs023.example".into(),
                        Bytes::from_static(b"RS023_PUBLIC_CA"),
                    )]),
                }),
                vec!["rs023.example", "RS023_PUBLIC_CA"],
            ),
            (
                formats(&delegated::SubscribeToJwtBundlesResponse {
                    bundles: HashMap::from([(
                        "rs023.example".into(),
                        Bytes::from_static(
                            br#"{"keys":[{"kty":"EC","x":"PUBLIC_X","y":"PUBLIC_Y"}]}"#,
                        ),
                    )]),
                }),
                vec!["rs023.example", "PUBLIC_X", "PUBLIC_Y"],
            ),
            (
                formats(&delegated::SubscribeToX509sviDsRequest {
                    selectors: vec![selector.clone()],
                    pid: 1234,
                }),
                vec!["unix", "uid:1234", "pid"],
            ),
            (
                formats(&delegated::FetchJwtsviDsRequest {
                    audience: vec!["public-audience".into()],
                    selectors: vec![selector.clone()],
                    pid: 1234,
                }),
                vec!["public-audience", "unix", "uid:1234", "pid"],
            ),
            (
                formats(&types::SelectorMatch {
                    selectors: vec![selector],
                    r#match: types::selector_match::MatchBehavior::MatchAny.into(),
                }),
                vec!["unix", "uid:1234", "MatchAny"],
            ),
        ];
        for (outputs, visible) in controls {
            for output in outputs {
                for text in &visible {
                    assert!(output.contains(text), "missing nonsecret metadata {text}");
                }
            }
        }
    }

    fn assert_wire<M: Message + Default + PartialEq + Debug>(name: &str, value: &M) {
        let encoded = value.encode_to_vec();
        let fixture = include_str!("testdata/protobuf_debug_wire.txt")
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find_map(|(label, bytes)| (label == name).then_some(bytes))
            .expect("original wire fixture exists");
        let original: Vec<u8> = fixture
            .split_whitespace()
            .map(|byte| u8::from_str_radix(byte, 16).expect("hex byte"))
            .collect();
        assert_eq!(encoded, original, "wire bytes changed for {name}");
        assert_eq!(value.encoded_len(), original.len());
        let decoded = M::decode(original.as_slice()).expect("original fixture decodes");
        assert_eq!(&decoded, value);
        assert_eq!(decoded.encode_to_vec(), original);
    }

    #[test]
    fn credential_wire_bytes_and_public_fields_are_unchanged() {
        // Struct literals above and typed field borrows below are external-consumer
        // checks for the existing public paths, construction syntax and field types.
        let ascii = x509(ASCII_KEY, "/first");
        let _: &Option<types::X509svid> = &ascii.x509_svid;
        let _: &Bytes = &ascii.x509_svid_key;
        let token = jwt(JWT, "/first");
        let _: &String = &token.token;
        let _: &Option<types::Spiffeid> = &token.id;
        let _: &i64 = &token.expires_at;
        let _: &i64 = &token.issued_at;
        let _: &String = &token.hint;

        assert_wire("x509-ascii", &ascii);
        assert_wire("x509-binary", &x509(BINARY_KEY, "/second"));
        assert_wire(
            "x509-absent",
            &delegated::X509svidWithKey {
                x509_svid: None,
                x509_svid_key: Bytes::from_static(BINARY_KEY),
            },
        );
        assert_wire("x509-empty-key", &x509(b"", "/empty"));
        assert_wire("x509-default", &delegated::X509svidWithKey::default());
        assert_wire("jwt", &token);
        assert_wire("jwt-escaped", &jwt(ESCAPED_JWT, "/second"));
        assert_wire(
            "jwt-absent",
            &types::Jwtsvid {
                id: None,
                ..token.clone()
            },
        );
        assert_wire("jwt-empty-token", &jwt("", "/empty"));
        assert_wire("jwt-default", &types::Jwtsvid::default());
        assert_wire(
            "x509-response-single",
            &delegated::SubscribeToX509sviDsResponse {
                x509_svids: vec![ascii.clone()],
                federates_with: vec!["federated.example".into()],
            },
        );
        assert_wire(
            "x509-response-multiple",
            &delegated::SubscribeToX509sviDsResponse {
                x509_svids: vec![ascii, x509(BINARY_KEY, "/second")],
                federates_with: vec!["federated.example".into()],
            },
        );
        assert_wire(
            "x509-response-empty",
            &delegated::SubscribeToX509sviDsResponse::default(),
        );
        assert_wire(
            "x509-response-default-entry",
            &delegated::SubscribeToX509sviDsResponse {
                x509_svids: vec![delegated::X509svidWithKey::default()],
                federates_with: Vec::new(),
            },
        );
        assert_wire(
            "jwt-response-single",
            &delegated::FetchJwtsviDsResponse {
                svids: vec![token.clone()],
            },
        );
        assert_wire(
            "jwt-response-multiple",
            &delegated::FetchJwtsviDsResponse {
                svids: vec![
                    token,
                    jwt(SECOND_JWT, "/second"),
                    jwt(ESCAPED_JWT, "/third"),
                ],
            },
        );
        assert_wire(
            "jwt-response-empty",
            &delegated::FetchJwtsviDsResponse::default(),
        );
        assert_wire(
            "jwt-response-default-entry",
            &delegated::FetchJwtsviDsResponse {
                svids: vec![types::Jwtsvid::default()],
            },
        );
    }
}
