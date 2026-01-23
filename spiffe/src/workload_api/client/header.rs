use tonic::metadata::{Ascii, MetadataKey, MetadataValue};

const SPIFFE_HEADER_KEY: &str = "workload.spiffe.io";
const SPIFFE_HEADER_VALUE: &str = "true";

// This is a fixed ASCII string literal, so `from_bytes()` should always succeed.
// If this constant is changed to non-ASCII, initialization will panic early at runtime.
static PARSED_HEADER_KEY: std::sync::LazyLock<MetadataKey<Ascii>> =
    std::sync::LazyLock::new(|| {
        #[allow(clippy::expect_used)]
        MetadataKey::from_bytes(SPIFFE_HEADER_KEY.as_bytes())
            .expect("SPIFFE_HEADER_KEY must be valid ASCII")
    });

static PARSED_HEADER_VALUE: std::sync::LazyLock<MetadataValue<Ascii>> =
    std::sync::LazyLock::new(|| MetadataValue::from_static(SPIFFE_HEADER_VALUE));

/// Tonic interceptor that adds the Workload API metadata header required by SPIRE.
#[derive(Clone)]
pub(super) struct MetadataAdder;

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
        Ok(request)
    }
}
