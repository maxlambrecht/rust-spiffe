//! Experimental bindings for the [SPIFFE Broker API].
//!
//! A broker, such as a node proxy, uses the Broker API to get SVIDs and bundles for the
//! workloads it serves. Every request names one workload with a [`WorkloadReference`].
//! Build one from a [`WorkloadPidReference`] or a [`KubernetesObjectReference`] with
//! [`From`], which also sets the type URL that providers match.
//!
//! The [SPIFFE Broker Endpoint] requires mutual TLS with X509-SVIDs, so the generated client
//! has no plaintext `connect` and the caller builds the [`tonic::transport::Channel`]. The
//! channel must check the provider's SPIFFE ID. Every request must also carry the security
//! header. Use [`SecurityHeader`] as the interceptor of the generated client:
//!
//! ```no_run
//! # fn example(channel: tonic::transport::Channel) {
//! use spiffe::broker_api::SecurityHeader;
//! use spiffe::broker_api::pb::spiffe::broker::{
//!     api_client::ApiClient, KubernetesObjectKey, KubernetesObjectReference,
//!     KubernetesObjectType, WorkloadReference,
//! };
//!
//! let _client = ApiClient::with_interceptor(channel, SecurityHeader::new());
//! let _pod = WorkloadReference::from(KubernetesObjectReference {
//!     r#type: Some(KubernetesObjectType {
//!         plural: "pods".into(),
//!         group: "core".into(),
//!     }),
//!     key: Some(KubernetesObjectKey {
//!         namespace: "default".into(),
//!         name: "web-0".into(),
//!     }),
//!     uid: "a1b2c3d4-0000-0000-0000-000000000000".into(),
//! });
//! # }
//! ```
//!
//! To add other metadata to each request, use [`SecurityHeader::with_interceptor`].
//!
//! This module is experimental, and semver guarantees do not cover it. The Broker API is new,
//! and SPIRE ships it under its `experimental` configuration, so a change to the specification
//! can bring a breaking change. The generated types also expose `prost` and `tonic`, so a major
//! upgrade of either can break users of this module.
//!
//! [`WorkloadReference`]: pb::spiffe::broker::WorkloadReference
//! [`WorkloadPidReference`]: pb::spiffe::broker::WorkloadPidReference
//! [`KubernetesObjectReference`]: pb::spiffe::broker::KubernetesObjectReference
//! [SPIFFE Broker API]: https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Broker_API.md
//! [SPIFFE Broker Endpoint]: https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Broker_Endpoint.md

use crate::broker_api::pb::spiffe::broker::{
    Jwtsvid, KubernetesObjectReference, WorkloadPidReference, WorkloadReference, X509svid,
};
use prost::Name;
use std::sync::Arc;
use tonic::metadata::{Ascii, MetadataKey, MetadataValue};

/// Generated protobuf bindings for the SPIFFE Broker API.
///
/// **This module contains generated code. Do not edit these files manually.**
///
/// Generated from `standards/brokerapi.proto` at spiffe/spiffe commit `69464c3`.
/// Regenerate with: `cargo run -p xtask -- gen spiffe` from the repo root.
#[expect(
    clippy::allow_attributes_without_reason,
    clippy::derive_partial_eq_without_eq,
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::too_long_first_doc_paragraph,
    missing_docs,
    unused_qualifications,
    unused_results
)]
pub mod pb {
    pub mod spiffe {
        pub mod broker {
            include!("pb/broker.rs");
        }
    }
}

const BROKER_HEADER_KEY: &str = "broker.spiffe.io";
const BROKER_HEADER_VALUE: &str = "true";

// These are fixed ASCII string literals, so parsing always succeeds.
static PARSED_HEADER_KEY: std::sync::LazyLock<MetadataKey<Ascii>> =
    std::sync::LazyLock::new(|| MetadataKey::from_static(BROKER_HEADER_KEY));

static PARSED_HEADER_VALUE: std::sync::LazyLock<MetadataValue<Ascii>> =
    std::sync::LazyLock::new(|| MetadataValue::from_static(BROKER_HEADER_VALUE));

/// Function that adds custom metadata to each request, for [`SecurityHeader::with_interceptor`].
pub type InterceptorFn =
    Arc<dyn Fn(&mut tonic::Request<()>) -> Result<(), tonic::Status> + Send + Sync>;

/// Interceptor that adds the Broker Endpoint security header, `broker.spiffe.io: true`, to
/// every request.
///
/// A provider rejects a request without this header with `InvalidArgument`.
#[derive(Clone, Default)]
pub struct SecurityHeader {
    extra: Option<InterceptorFn>,
}

impl SecurityHeader {
    /// Adds only the security header.
    pub fn new() -> Self {
        Self::default()
    }

    /// Runs `extra` on every request, then adds the security header.
    ///
    /// `extra` runs first, so it cannot remove or overwrite the security header.
    pub fn with_interceptor(extra: InterceptorFn) -> Self {
        Self { extra: Some(extra) }
    }
}

impl std::fmt::Debug for SecurityHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecurityHeader")
            .field("extra", &self.extra.is_some())
            .finish()
    }
}

impl tonic::service::Interceptor for SecurityHeader {
    fn call(
        &mut self,
        mut request: tonic::Request<()>,
    ) -> Result<tonic::Request<()>, tonic::Status> {
        if let Some(extra) = &self.extra {
            extra(&mut request)?;
        }
        request
            .metadata_mut()
            .insert(PARSED_HEADER_KEY.clone(), PARSED_HEADER_VALUE.clone());
        Ok(request)
    }
}

impl From<WorkloadPidReference> for WorkloadReference {
    fn from(reference: WorkloadPidReference) -> Self {
        pack(&reference)
    }
}

impl From<KubernetesObjectReference> for WorkloadReference {
    fn from(reference: KubernetesObjectReference) -> Self {
        pack(&reference)
    }
}

// The SVID messages skip the generated `Debug`, so their private key or token never
// reaches a log. Like `PrivateKey` and the JWT `Token`, they show only the length of the key
// or token.
impl std::fmt::Debug for X509svid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X509svid")
            .field("spiffe_id", &self.spiffe_id)
            .field("x509_svid", &self.x509_svid)
            .field(
                "x509_svid_key",
                &Redacted("PrivateKey", self.x509_svid_key.len()),
            )
            .field("bundle", &self.bundle)
            .field("hint", &self.hint)
            .finish()
    }
}

impl std::fmt::Debug for Jwtsvid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Jwtsvid")
            .field("spiffe_id", &self.spiffe_id)
            .field("svid", &Redacted("Token", self.svid.len()))
            .field("hint", &self.hint)
            .finish()
    }
}

struct Redacted(&'static str, usize);

impl std::fmt::Debug for Redacted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct(self.0).field("len", &self.1).finish()
    }
}

fn pack<M: Name>(reference: &M) -> WorkloadReference {
    WorkloadReference {
        reference: Some(prost_types::Any {
            type_url: M::type_url(),
            value: reference.encode_to_vec(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker_api::pb::spiffe::broker::{KubernetesObjectKey, KubernetesObjectType};
    use tonic::service::Interceptor as _;

    fn pod() -> KubernetesObjectReference {
        KubernetesObjectReference {
            r#type: Some(KubernetesObjectType {
                plural: "pods".into(),
                group: "core".into(),
            }),
            key: Some(KubernetesObjectKey {
                namespace: "default".into(),
                name: "web-0".into(),
            }),
            uid: "a1b2c3d4".into(),
        }
    }

    // SPIRE matches these exact strings; a missing domain is rejected as unsupported.
    #[test]
    fn references_carry_full_type_urls() {
        let pid = WorkloadReference::from(WorkloadPidReference { pid: 42 });
        assert_eq!(
            pid.reference.unwrap().type_url,
            "type.googleapis.com/spiffe.broker.WorkloadPIDReference"
        );
        let object = WorkloadReference::from(pod());
        assert_eq!(
            object.reference.unwrap().type_url,
            "type.googleapis.com/spiffe.broker.KubernetesObjectReference"
        );
    }

    #[test]
    fn kubernetes_reference_round_trips() {
        let any = WorkloadReference::from(pod()).reference.unwrap();
        assert_eq!(any.to_msg::<KubernetesObjectReference>().unwrap(), pod());
    }

    #[test]
    fn debug_hides_svid_secrets() {
        let x509 = X509svid {
            spiffe_id: "spiffe://td/w".into(),
            x509_svid: "chain".into(),
            x509_svid_key: "SECRET-KEY".into(),
            bundle: "roots".into(),
            hint: "internal".into(),
        };
        assert_eq!(
            format!("{x509:?}"),
            r#"X509svid { spiffe_id: "spiffe://td/w", x509_svid: b"chain", x509_svid_key: PrivateKey { len: 10 }, bundle: b"roots", hint: "internal" }"#
        );
        let jwt = Jwtsvid {
            spiffe_id: "spiffe://td/w".into(),
            svid: "SECRET-TOKEN".into(),
            hint: "internal".into(),
        };
        assert_eq!(
            format!("{jwt:?}"),
            r#"Jwtsvid { spiffe_id: "spiffe://td/w", svid: Token { len: 12 }, hint: "internal" }"#
        );
    }

    #[test]
    fn security_header_always_inserted() {
        let request = SecurityHeader::new()
            .call(tonic::Request::new(()))
            .expect("interceptor should succeed");
        assert_eq!(
            request.metadata().get(BROKER_HEADER_KEY).expect("present"),
            BROKER_HEADER_VALUE,
        );
    }

    #[test]
    fn custom_interceptor_metadata_added() {
        let interceptor: InterceptorFn = Arc::new(|req| {
            req.metadata_mut().insert(
                MetadataKey::from_static("authorization"),
                MetadataValue::from_static("Bearer test-token"),
            );
            Ok(())
        });
        let request = SecurityHeader::with_interceptor(interceptor)
            .call(tonic::Request::new(()))
            .expect("interceptor should succeed");
        assert_eq!(
            request.metadata().get(BROKER_HEADER_KEY).expect("present"),
            BROKER_HEADER_VALUE,
        );
        assert_eq!(
            request.metadata().get("authorization").expect("present"),
            "Bearer test-token",
        );
    }

    #[test]
    fn security_header_preserved_when_custom_interceptor_overwrites_it() {
        let interceptor: InterceptorFn = Arc::new(|req| {
            req.metadata_mut().remove(BROKER_HEADER_KEY);
            req.metadata_mut().insert(
                MetadataKey::from_static(BROKER_HEADER_KEY),
                MetadataValue::from_static("false"),
            );
            Ok(())
        });
        let request = SecurityHeader::with_interceptor(interceptor)
            .call(tonic::Request::new(()))
            .expect("interceptor should succeed");
        assert_eq!(
            request.metadata().get(BROKER_HEADER_KEY).expect("present"),
            BROKER_HEADER_VALUE,
        );
    }

    #[test]
    fn custom_interceptor_error_propagates() {
        let interceptor: InterceptorFn =
            Arc::new(|_| Err(tonic::Status::internal("token expired")));
        let err = SecurityHeader::with_interceptor(interceptor)
            .call(tonic::Request::new(()))
            .expect_err("interceptor should fail");
        assert_eq!(err.code(), tonic::Code::Internal);
        assert_eq!(err.message(), "token expired");
    }
}
