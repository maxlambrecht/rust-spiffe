use std::sync::Arc;

use tonic::metadata::{Ascii, MetadataKey, MetadataValue};

const SPIFFE_HEADER_KEY: &str = "workload.spiffe.io";
const SPIFFE_HEADER_VALUE: &str = "true";

// This is a fixed ASCII string literal, so `from_bytes()` should always succeed.
// If this constant is changed to non-ASCII, initialization will panic early at runtime.
static PARSED_HEADER_KEY: std::sync::LazyLock<MetadataKey<Ascii>> =
    std::sync::LazyLock::new(|| MetadataKey::from_static(SPIFFE_HEADER_KEY));

static PARSED_HEADER_VALUE: std::sync::LazyLock<MetadataValue<Ascii>> =
    std::sync::LazyLock::new(|| MetadataValue::from_static(SPIFFE_HEADER_VALUE));

/// Per-RPC metadata interceptor function type.
///
/// Called on every gRPC request to inject custom metadata (e.g. K8s SA
/// tokens for identity-server authentication).
pub type InterceptorFn =
    Arc<dyn Fn(&mut tonic::Request<()>) -> Result<(), tonic::Status> + Send + Sync>;

/// Tonic interceptor that adds the Workload API metadata header required
/// by SPIRE, plus optional custom per-RPC metadata.
///
/// The `extra` field supports identity-server's transport model where
/// callers must provide authentication tokens on every RPC.
#[derive(Clone)]
pub(super) struct MetadataAdder {
    extra: Option<InterceptorFn>,
}

impl MetadataAdder {
    pub(super) fn new(extra: Option<InterceptorFn>) -> Self {
        Self { extra }
    }
}

impl tonic::service::Interceptor for MetadataAdder {
    fn call(
        &mut self,
        mut request: tonic::Request<()>,
    ) -> Result<tonic::Request<()>, tonic::Status> {
        // Cloning is required: tonic's metadata insert() takes owned values.
        // The LazyLock ensures these are only parsed once at initialization.
        request
            .metadata_mut()
            .insert(PARSED_HEADER_KEY.clone(), PARSED_HEADER_VALUE.clone());

        // Apply custom per-RPC metadata if provided.
        if let Some(extra) = &self.extra {
            extra(&mut request)?;
        }

        Ok(request)
    }
}
