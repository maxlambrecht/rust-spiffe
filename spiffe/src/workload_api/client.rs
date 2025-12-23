//! Workload API client for fetching SPIFFE X.509 and JWT material.
//!
//! `WorkloadApiClient` provides one-shot RPCs (fetch SVIDs/bundles) and streaming RPCs for
//! receiving updates as material rotates.
//!
//! Most users should prefer higher-level types like `X509Source`, which handle reconnection and
//! provide an always-up-to-date view of the X.509 context.
//!
//! # Example
//!
//! ```no_run
//! use spiffe::{SpiffeId, WorkloadApiClient};
//! use tokio_stream::StreamExt;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//! let mut client =
//!     WorkloadApiClient::new_from_path("unix:/tmp/spire-agent/public/api.sock").await?;
//!
//! let jwt = client.fetch_jwt_token(&["service1"], None).await?;
//! let _jwt_svid = client.fetch_jwt_svid(&["service1"], None).await?;
//! let _jwt_bundles = client.fetch_jwt_bundles().await?;
//!
//! let _x509_svid = client.fetch_x509_svid().await?;
//! let _x509_bundles = client.fetch_x509_bundles().await?;
//! let _x509_ctx = client.fetch_x509_context().await?;
//!
//! let mut updates = client.stream_x509_contexts().await?;
//! while let Some(update) = updates.next().await {
//!     let _ctx = update?;
//! }
//! # Ok(())
//! # }
//! ```

use std::str::FromStr;

use crate::bundle::jwt::{JwtBundle, JwtBundleSet};
use crate::bundle::x509::{X509Bundle, X509BundleSet};
use crate::endpoint::{get_default_socket_path, validate_socket_path};
use crate::spiffe_id::{SpiffeId, TrustDomain};
use crate::svid::jwt::JwtSvid;
use crate::svid::x509::X509Svid;
use crate::workload_api::x509_context::X509Context;
use hyper_util::rt::TokioIo;
use std::convert::TryFrom;
use std::sync::Arc;
use tokio::net::UnixStream;
use tokio_stream::{Stream, StreamExt};

use crate::constants::DEFAULT_SVID;
use crate::error::GrpcClientError;
use crate::proto::workload::spiffe_workload_api_client::SpiffeWorkloadApiClient;
use crate::proto::workload::{
    JwtBundlesRequest, JwtBundlesResponse, JwtsvidRequest, JwtsvidResponse, ValidateJwtsvidRequest,
    ValidateJwtsvidResponse, X509BundlesRequest, X509BundlesResponse, X509svidRequest,
    X509svidResponse,
};
use tonic::transport::{Endpoint, Uri};
use tower::service_fn;

const SPIFFE_HEADER_KEY: &str = "workload.spiffe.io";
const SPIFFE_HEADER_VALUE: &str = "true";

/// Client for the SPIFFE Workload API.
///
/// Provides one-shot calls and streaming updates for X.509 and JWT SVIDs and bundles.
/// For an always-up-to-date, shareable source of X.509 material with automatic reconnection,
/// see [`crate::X509Source`].
#[derive(Debug, Clone)]
pub struct WorkloadApiClient {
    socket_path: Arc<str>,
    client: SpiffeWorkloadApiClient<
        tonic::service::interceptor::InterceptedService<tonic::transport::Channel, MetadataAdder>,
    >,
}

/// Tonic interceptor that adds the Workload API metadata header required by SPIRE.
#[derive(Clone)]
struct MetadataAdder;

impl tonic::service::Interceptor for MetadataAdder {
    fn call(
        &mut self,
        mut request: tonic::Request<()>,
    ) -> Result<tonic::Request<()>, tonic::Status> {
        let parsed_header = SPIFFE_HEADER_VALUE
            .parse()
            .map_err(|e| tonic::Status::internal(format!("Failed to parse header: {e}")))?;
        request
            .metadata_mut()
            .insert(SPIFFE_HEADER_KEY, parsed_header);
        Ok(request)
    }
}

impl WorkloadApiClient {
    const UNIX_PREFIX: &'static str = "unix:";
    const TONIC_DEFAULT_URI: &'static str = "http://[::]:50051";

    /// Returns the configured Workload API socket path.
    pub fn socket_path(&self) -> &str {
        &self.socket_path
    }

    async fn connect_channel(
        socket_path: &str,
    ) -> Result<tonic::transport::Channel, GrpcClientError> {
        validate_socket_path(socket_path)?;

        // Strip the 'unix:' prefix for tonic compatibility.
        let stripped = socket_path
            .strip_prefix(Self::UNIX_PREFIX)
            .unwrap_or(socket_path)
            .to_string();

        let channel = Endpoint::try_from(Self::TONIC_DEFAULT_URI)?
            .connect_with_connector(service_fn(move |_: Uri| {
                let stripped = stripped.clone();
                async { UnixStream::connect(stripped).await.map(TokioIo::new) }
            }))
            .await?;

        Ok(channel)
    }

    /// Connects to the Workload API using the given UNIX domain socket path.
    ///
    /// The path may optionally be prefixed with `unix:` (e.g. `unix:/tmp/spire-agent/public/api.sock`).
    pub async fn new_from_path(path: impl AsRef<str>) -> Result<Self, GrpcClientError> {
        let path = path.as_ref();
        validate_socket_path(path)?;

        let socket_path: Arc<str> = Arc::from(path);
        let channel = Self::connect_channel(path).await?;

        Ok(WorkloadApiClient {
            socket_path,
            client: SpiffeWorkloadApiClient::with_interceptor(channel, MetadataAdder {}),
        })
    }

    /// Rebuilds the underlying gRPC channel.
    ///
    /// This is intended for manual recovery scenarios. Higher-level abstractions such as `X509Source`
    /// typically create fresh clients and manage reconnection automatically.
    pub async fn reconnect(&mut self) -> Result<(), GrpcClientError> {
        let channel = Self::connect_channel(&self.socket_path).await?;
        self.client = SpiffeWorkloadApiClient::with_interceptor(channel, MetadataAdder {});
        Ok(())
    }

    /// Connects to the Workload API using `SPIFFE_ENDPOINT_SOCKET`.
    pub async fn default() -> Result<Self, GrpcClientError> {
        let socket_path =
            get_default_socket_path().ok_or(GrpcClientError::MissingEndpointSocketPath)?;
        Self::new_from_path(socket_path.as_str()).await
    }

    /// Creates a client from an existing gRPC channel.
    ///
    /// This is primarily useful for tests or advanced transport customization.
    pub fn new(
        socket_path: impl AsRef<str>,
        conn: tonic::transport::Channel,
    ) -> Result<Self, GrpcClientError> {
        Ok(WorkloadApiClient {
            socket_path: Arc::from(socket_path.as_ref()),
            client: SpiffeWorkloadApiClient::with_interceptor(conn, MetadataAdder {}),
        })
    }

    /// Fetches the default X.509 SVID for the calling workload.
    pub async fn fetch_x509_svid(&mut self) -> Result<X509Svid, GrpcClientError> {
        let request = X509svidRequest::default();

        let grpc_stream_response: tonic::Response<tonic::Streaming<X509svidResponse>> =
            self.client.fetch_x509svid(request).await?;

        let response = grpc_stream_response
            .into_inner()
            .message()
            .await?
            .ok_or(GrpcClientError::EmptyResponse)?;
        WorkloadApiClient::parse_x509_svid_from_grpc_response(response)
    }

    /// Fetches all X.509 SVIDs available to the calling workload.
    pub async fn fetch_all_x509_svids(&mut self) -> Result<Vec<X509Svid>, GrpcClientError> {
        let request = X509svidRequest::default();

        let grpc_stream_response: tonic::Response<tonic::Streaming<X509svidResponse>> =
            self.client.fetch_x509svid(request).await?;

        let response = grpc_stream_response
            .into_inner()
            .message()
            .await?
            .ok_or(GrpcClientError::EmptyResponse)?;
        WorkloadApiClient::parse_x509_svids_from_grpc_response(response)
    }

    /// Fetches the current X.509 bundle set.
    pub async fn fetch_x509_bundles(&mut self) -> Result<X509BundleSet, GrpcClientError> {
        let request = X509BundlesRequest::default();

        let grpc_stream_response: tonic::Response<tonic::Streaming<X509BundlesResponse>> =
            self.client.fetch_x509_bundles(request).await?;

        let response = grpc_stream_response
            .into_inner()
            .message()
            .await?
            .ok_or(GrpcClientError::EmptyResponse)?;
        WorkloadApiClient::parse_x509_bundle_set_from_grpc_response(response)
    }

    /// Fetches the current JWT bundle set.
    pub async fn fetch_jwt_bundles(&mut self) -> Result<JwtBundleSet, GrpcClientError> {
        let request = JwtBundlesRequest::default();

        let grpc_stream_response: tonic::Response<tonic::Streaming<JwtBundlesResponse>> =
            self.client.fetch_jwt_bundles(request).await?;

        let response = grpc_stream_response
            .into_inner()
            .message()
            .await?
            .ok_or(GrpcClientError::EmptyResponse)?;
        WorkloadApiClient::parse_jwt_bundle_set_from_grpc_response(response)
    }

    /// Fetches the current X.509 context (SVIDs and bundles).
    pub async fn fetch_x509_context(&mut self) -> Result<X509Context, GrpcClientError> {
        let request = X509svidRequest::default();

        let grpc_stream_response: tonic::Response<tonic::Streaming<X509svidResponse>> =
            self.client.fetch_x509svid(request).await?;

        let response = grpc_stream_response
            .into_inner()
            .message()
            .await?
            .ok_or(GrpcClientError::EmptyResponse)?;
        WorkloadApiClient::parse_x509_context_from_grpc_response(response)
    }

    /// Fetches a JWT-SVID for the given audience and optional SPIFFE ID.
    ///
    /// If `spiffe_id` is `None`, the Workload API returns the default identity.
    pub async fn fetch_jwt_svid<T: AsRef<str> + ToString>(
        &mut self,
        audience: &[T],
        spiffe_id: Option<&SpiffeId>,
    ) -> Result<JwtSvid, GrpcClientError> {
        let response = self.fetch_jwt(audience, spiffe_id).await?;
        response
            .svids
            .get(DEFAULT_SVID)
            .ok_or(GrpcClientError::EmptyResponse)
            .and_then(|r| JwtSvid::from_str(&r.svid).map_err(GrpcClientError::JwtSvid))
    }

    /// Fetches a JWT-SVID token string for the given audience and optional SPIFFE ID.
    ///
    /// If `spiffe_id` is `None`, the Workload API returns the default identity.
    pub async fn fetch_jwt_token<T: AsRef<str> + ToString>(
        &mut self,
        audience: &[T],
        spiffe_id: Option<&SpiffeId>,
    ) -> Result<String, GrpcClientError> {
        let response = self.fetch_jwt(audience, spiffe_id).await?;
        response
            .svids
            .get(DEFAULT_SVID)
            .map(|r| r.svid.to_string())
            .ok_or(GrpcClientError::EmptyResponse)
    }

    /// Validates a JWT-SVID token for the given audience and returns the parsed `JwtSvid`.
    pub async fn validate_jwt_token<T: AsRef<str> + ToString>(
        &mut self,
        audience: T,
        jwt_token: &str,
    ) -> Result<JwtSvid, GrpcClientError> {
        // validate token with Workload API, the returned claims and spiffe_id are ignored as
        // they are parsed from token when the `JwtSvid` object is created, this way we avoid having
        // to validate that the response from the Workload API contains correct claims.
        let _ = self.validate_jwt(audience, jwt_token).await?;
        let jwt_svid = JwtSvid::parse_insecure(jwt_token)?;
        Ok(jwt_svid)
    }

    /// Streams X.509 context updates from the Workload API.
    pub async fn stream_x509_contexts(
        &mut self,
    ) -> Result<impl Stream<Item = Result<X509Context, GrpcClientError>>, GrpcClientError> {
        let request = X509svidRequest::default();
        let response = self.client.fetch_x509svid(request).await?;
        let stream = response.into_inner().map(|message| {
            message
                .map_err(GrpcClientError::from)
                .and_then(WorkloadApiClient::parse_x509_context_from_grpc_response)
        });
        Ok(stream)
    }

    /// Streams X.509 SVID updates from the Workload API.
    pub async fn stream_x509_svids(
        &mut self,
    ) -> Result<impl Stream<Item = Result<X509Svid, GrpcClientError>>, GrpcClientError> {
        let request = X509svidRequest::default();
        let response = self.client.fetch_x509svid(request).await?;
        let stream = response.into_inner().map(|message| {
            message
                .map_err(GrpcClientError::from)
                .and_then(WorkloadApiClient::parse_x509_svid_from_grpc_response)
        });
        Ok(stream)
    }

    /// Streams X.509 bundle set updates from the Workload API.
    pub async fn stream_x509_bundles(
        &mut self,
    ) -> Result<impl Stream<Item = Result<X509BundleSet, GrpcClientError>>, GrpcClientError> {
        let request = X509BundlesRequest::default();
        let response = self.client.fetch_x509_bundles(request).await?;
        let stream = response.into_inner().map(|message| {
            message
                .map_err(GrpcClientError::from)
                .and_then(WorkloadApiClient::parse_x509_bundle_set_from_grpc_response)
        });
        Ok(stream)
    }

    /// Streams JWT bundle set updates from the Workload API.
    pub async fn stream_jwt_bundles(
        &mut self,
    ) -> Result<impl Stream<Item = Result<JwtBundleSet, GrpcClientError>>, GrpcClientError> {
        let request = JwtBundlesRequest::default();
        let response = self.client.fetch_jwt_bundles(request).await?;
        let stream = response.into_inner().map(|message| {
            message
                .map_err(GrpcClientError::from)
                .and_then(WorkloadApiClient::parse_jwt_bundle_set_from_grpc_response)
        });
        Ok(stream)
    }
}

/// private
impl WorkloadApiClient {
    async fn fetch_jwt<T: AsRef<str> + ToString>(
        &mut self,
        audience: &[T],
        spiffe_id: Option<&SpiffeId>,
    ) -> Result<JwtsvidResponse, GrpcClientError> {
        let request = JwtsvidRequest {
            spiffe_id: spiffe_id.map(ToString::to_string).unwrap_or_default(),
            audience: audience.iter().map(|s| s.to_string()).collect(),
        };

        Ok(self.client.fetch_jwtsvid(request).await?.into_inner())
    }

    async fn validate_jwt<T: AsRef<str>>(
        &mut self,
        audience: T,
        jwt_svid: &str,
    ) -> Result<ValidateJwtsvidResponse, GrpcClientError> {
        let request = ValidateJwtsvidRequest {
            audience: audience.as_ref().into(),
            svid: jwt_svid.into(),
        };

        Ok(self.client.validate_jwtsvid(request).await?.into_inner())
    }

    fn parse_x509_svid_from_grpc_response(
        response: X509svidResponse,
    ) -> Result<X509Svid, GrpcClientError> {
        let svid = response
            .svids
            .get(DEFAULT_SVID)
            .ok_or(GrpcClientError::EmptyResponse)?;

        X509Svid::parse_from_der(svid.x509_svid.as_ref(), svid.x509_svid_key.as_ref())
            .map_err(GrpcClientError::from)
    }

    fn parse_x509_svids_from_grpc_response(
        response: X509svidResponse,
    ) -> Result<Vec<X509Svid>, GrpcClientError> {
        let mut svids_vec = Vec::new();

        for svid in response.svids.iter() {
            let parsed_svid =
                X509Svid::parse_from_der(svid.x509_svid.as_ref(), svid.x509_svid_key.as_ref())
                    .map_err(GrpcClientError::from)?;

            svids_vec.push(parsed_svid);
        }

        Ok(svids_vec)
    }

    fn parse_x509_bundle_set_from_grpc_response(
        response: X509BundlesResponse,
    ) -> Result<X509BundleSet, GrpcClientError> {
        let bundles: Result<Vec<_>, _> = response
            .bundles
            .into_iter()
            .map(|(td, bundle_data)| {
                let trust_domain = TrustDomain::try_from(td)?;
                X509Bundle::parse_from_der(trust_domain, &bundle_data)
                    .map_err(GrpcClientError::from)
            })
            .collect();

        let mut bundle_set = X509BundleSet::new();
        for bundle in bundles? {
            bundle_set.add_bundle(bundle);
        }

        Ok(bundle_set)
    }

    fn parse_jwt_bundle_set_from_grpc_response(
        response: JwtBundlesResponse,
    ) -> Result<JwtBundleSet, GrpcClientError> {
        let mut bundle_set = JwtBundleSet::new();

        for (td, bundle_data) in response.bundles.into_iter() {
            let trust_domain = TrustDomain::try_from(td)?;
            let bundle = JwtBundle::from_jwt_authorities(trust_domain, &bundle_data)
                .map_err(GrpcClientError::from)?;

            bundle_set.add_bundle(bundle);
        }

        Ok(bundle_set)
    }

    fn parse_x509_context_from_grpc_response(
        response: X509svidResponse,
    ) -> Result<X509Context, GrpcClientError> {
        let mut svids = Vec::new();
        let mut bundle_set = X509BundleSet::new();

        for svid in response.svids.into_iter() {
            let x509_svid =
                X509Svid::parse_from_der(svid.x509_svid.as_ref(), svid.x509_svid_key.as_ref())
                    .map_err(GrpcClientError::from)?;

            let trust_domain = x509_svid.spiffe_id().trust_domain().clone();
            svids.push(x509_svid);

            let bundle = X509Bundle::parse_from_der(trust_domain, svid.bundle.as_ref())
                .map_err(GrpcClientError::from)?;
            bundle_set.add_bundle(bundle);
        }

        for (trust_domain, bundle) in response.federated_bundles.into_iter() {
            let trust_domain = TrustDomain::try_from(trust_domain)?;
            let x509_bundle = X509Bundle::parse_from_der(trust_domain, bundle.as_ref())
                .map_err(GrpcClientError::from)?;
            bundle_set.add_bundle(x509_bundle);
        }

        Ok(X509Context::new(svids, bundle_set))
    }
}
