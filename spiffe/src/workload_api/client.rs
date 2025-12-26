//! Workload API client for fetching SPIFFE X.509 and JWT material.
//!
//! `WorkloadApiClient` provides one-shot RPCs (fetch SVIDs/bundles) and streaming RPCs for
//! receiving updates as material rotates.
//!
//! Most users should prefer higher-level types like [`X509Source`], which handle reconnection
//! and provide an always-up-to-date view of the X.509 context.
//!
//! ## Multiple SVIDs and hints
//!
//! A single workload may be issued **multiple SVIDs** by the SPIFFE Workload API.
//! When this happens, the agent may attach an optional **hint** to each SVID to help
//! distinguish identities (for example `"internal"` vs `"external"`).
//!
//! Hints are **not part of the cryptographic material** and have no security meaning.
//! They are exposed as metadata on [`X509Svid`] and [`JwtSvid`] for selection logic only.
//!
//! If multiple identities are expected, prefer APIs that return **all SVIDs**, or select
//! explicitly by hint. For long-running workloads, use [`X509Source`] with a custom
//! [`SvidPicker`].
//!
//! # Example
//!
//! ```no_run
//! use spiffe::WorkloadApiClient;
//! use tokio_stream::StreamExt;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//! let mut client = WorkloadApiClient::connect_to("unix:/tmp/spire-agent/public/api.sock").await?;
//!
//! let _jwt = client.fetch_jwt_token(&["service1"], None).await?;
//! let _jwt_svid = client.fetch_jwt_svid(&["service1"], None).await?;
//!
//! let _x509_svid = client.fetch_x509_svid().await?;
//! let _x509_ctx = client.fetch_x509_context().await?;
//!
//! let mut updates = client.stream_x509_contexts().await?;
//! while let Some(update) = updates.next().await {
//!     let _ctx = update?;
//! }
//! # Ok(())
//! # }
//! ```

use std::convert::TryFrom;
use std::str::FromStr;
use std::sync::Arc;

use tokio_stream::{Stream, StreamExt};

use crate::bundle::jwt::{JwtBundle, JwtBundleSet};
use crate::bundle::x509::{X509Bundle, X509BundleSet};
use crate::constants::DEFAULT_SVID;
use crate::endpoint::Endpoint;
use crate::error::GrpcClientError;
use crate::grpc::connector;
use crate::spiffe_id::{SpiffeId, TrustDomain};
use crate::svid::jwt::JwtSvid;
use crate::svid::x509::X509Svid;
use crate::workload_api::pb::workload::spiffe_workload_api_client::SpiffeWorkloadApiClient;
use crate::workload_api::pb::workload::{
    JwtBundlesRequest, JwtBundlesResponse, JwtsvidRequest, JwtsvidResponse, ValidateJwtsvidRequest,
    ValidateJwtsvidResponse, X509BundlesRequest, X509BundlesResponse, X509svidRequest,
    X509svidResponse,
};
use crate::workload_api::x509_context::X509Context;

const SPIFFE_HEADER_KEY: &str = "workload.spiffe.io";
const SPIFFE_HEADER_VALUE: &str = "true";

/// Client for the SPIFFE Workload API.
///
/// Provides one-shot calls and streaming updates for X.509 and JWT SVIDs and bundles.
/// For an always-up-to-date, shareable source of X.509 material with automatic reconnection,
/// see [`crate::X509Source`].
#[derive(Debug, Clone)]
pub struct WorkloadApiClient {
    endpoint: Arc<Endpoint>,
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
    /// Returns the configured Workload API endpoint.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Connects to the Workload API using a parsed [`WorkloadApiEndpoint`].
    ///
    /// # Errors
    ///
    /// Returns a [`GrpcClientError`] if the endpoint cannot be reached or the gRPC
    /// connection fails.
    pub async fn connect(endpoint: Endpoint) -> Result<Self, GrpcClientError> {
        let channel = connector::connect(&endpoint).await?;
        Ok(Self {
            endpoint: Arc::new(endpoint),
            client: SpiffeWorkloadApiClient::with_interceptor(channel, MetadataAdder {}),
        })
    }

    /// Connects to the Workload API using the given endpoint string.
    ///
    /// Examples:
    /// - `unix:/tmp/spire-agent/public/api.sock`
    /// - `tcp:127.0.0.1:8081`
    ///
    /// # Errors
    ///
    /// Returns a [`GrpcClientError`] if the endpoint string is invalid, the endpoint
    /// cannot be reached, or the gRPC connection fails.
    pub async fn connect_to(endpoint: impl AsRef<str>) -> Result<Self, GrpcClientError> {
        let endpoint = Endpoint::parse(endpoint.as_ref())?;
        Self::connect(endpoint).await
    }

    /// Connects to the Workload API using `SPIFFE_ENDPOINT_SOCKET`.
    ///
    /// # Errors
    ///
    /// Returns a [`GrpcClientError`] if the endpoint socket is not set, cannot be
    /// reached, or the gRPC connection fails.
    pub async fn connect_env() -> Result<Self, GrpcClientError> {
        let endpoint = crate::workload_api::endpoint::from_env()?;
        Self::connect(endpoint).await
    }

    /// Rebuilds the underlying gRPC channel.
    ///
    /// This is intended for manual recovery scenarios. Higher-level abstractions
    /// such as `X509Source` typically create fresh clients and manage reconnection
    /// automatically.
    ///
    /// # Errors
    ///
    /// Returns a [`GrpcClientError`] if the gRPC channel cannot be rebuilt.
    pub async fn reconnect(&mut self) -> Result<(), GrpcClientError> {
        let channel = connector::connect(&self.endpoint).await?;
        self.client = SpiffeWorkloadApiClient::with_interceptor(channel, MetadataAdder {});
        Ok(())
    }

    /// Creates a client from an existing gRPC channel.
    ///
    /// This is primarily intended for tests or advanced transport customization.
    pub fn new(endpoint: Endpoint, conn: tonic::transport::Channel) -> Self {
        Self {
            endpoint: Arc::new(endpoint),
            client: SpiffeWorkloadApiClient::with_interceptor(conn, MetadataAdder {}),
        }
    }

    /// Fetches the default X.509 SVID for the calling workload from the SPIFFE Workload API.
    ///
    /// # Errors
    ///
    /// Returns a [`GrpcClientError`] if the gRPC request fails, the response stream
    /// ends unexpectedly, or the received data is invalid.
    pub async fn fetch_x509_svid(&mut self) -> Result<X509Svid, GrpcClientError> {
        let request = X509svidRequest::default();

        let grpc_stream_response: tonic::Response<tonic::Streaming<X509svidResponse>> =
            self.client.fetch_x509svid(request).await?;

        let resp = grpc_stream_response
            .into_inner()
            .message()
            .await?
            .ok_or(GrpcClientError::EmptyResponse)?;
        WorkloadApiClient::parse_x509_svid_from_grpc_response(&resp)
    }

    /// Fetches all X.509 SVIDs available to the calling workload from the SPIFFE Workload API.
    ///
    /// # Errors
    ///
    /// Returns a [`GrpcClientError`] if the gRPC request fails, the response stream
    /// ends unexpectedly, or the received data is invalid.
    pub async fn fetch_all_x509_svids(&mut self) -> Result<Vec<X509Svid>, GrpcClientError> {
        let request = X509svidRequest::default();

        let grpc_stream_response: tonic::Response<tonic::Streaming<X509svidResponse>> =
            self.client.fetch_x509svid(request).await?;

        let response = grpc_stream_response
            .into_inner()
            .message()
            .await?
            .ok_or(GrpcClientError::EmptyResponse)?;
        WorkloadApiClient::parse_x509_svids_from_grpc_response(&response)
    }

    /// Fetches the current X.509 bundle set from the SPIFFE Workload API.
    ///
    /// # Errors
    ///
    /// Returns a [`GrpcClientError`] if the gRPC request fails, the response stream
    /// ends unexpectedly, or the received data is invalid.
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

    /// Fetches the current set of JWT bundles from the SPIFFE Workload API.
    ///
    /// This method establishes a streaming gRPC request to the Workload API
    /// and returns the latest JWT bundle set received from the server.
    ///
    /// # Errors
    ///
    /// Returns a [`GrpcClientError`] if the gRPC request fails, the stream
    /// terminates unexpectedly, or an invalid response is received.
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
    ///
    /// # Errors
    ///
    /// Returns a [`GrpcClientError`] if the Workload API request fails, the response
    /// stream terminates unexpectedly, or the received data cannot be parsed.
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

    /// Fetches a `JwtSvid` for the given audience and optional SPIFFE ID.
    ///
    /// If `spiffe_id` is `None`, the Workload API returns the default identity.
    ///
    /// # Errors
    ///
    /// Returns a [`GrpcClientError`] if the JWT-SVID request fails or the Workload API
    /// returns an invalid or empty response.
    pub async fn fetch_jwt_svid<T: AsRef<str> + ToString>(
        &mut self,
        audience: &[T],
        spiffe_id: Option<&SpiffeId>,
    ) -> Result<JwtSvid, GrpcClientError> {
        let response = self.fetch_jwt(audience, spiffe_id).await?;
        let r = response
            .svids
            .get(DEFAULT_SVID)
            .ok_or(GrpcClientError::EmptyResponse)?;

        let mut svid = JwtSvid::from_str(&r.svid).map_err(GrpcClientError::JwtSvid)?;

        if !r.hint.is_empty() {
            svid = svid.with_hint(Arc::<str>::from(r.hint.as_str()));
        }

        Ok(svid)
    }

    /// Fetches all JWT-SVIDs for the given audience and optional SPIFFE ID.
    ///
    /// The Workload API can return more than one JWT-SVID. Each returned [`JwtSvid`] may include an
    /// optional **hint** (via [`JwtSvid::hint`]) that can be used to disambiguate which SVID to use.
    ///
    /// If `spiffe_id` is `None`, the Workload API returns JWT-SVIDs for the default identity.
    ///
    /// # Errors
    ///
    /// Returns a [`GrpcClientError`] if the JWT-SVID request fails, the Workload API response is
    /// invalid or empty, or any returned token cannot be parsed.
    pub async fn fetch_all_jwt_svids<T: AsRef<str> + ToString>(
        &mut self,
        audience: &[T],
        spiffe_id: Option<&SpiffeId>,
    ) -> Result<Vec<JwtSvid>, GrpcClientError> {
        let response = self.fetch_jwt(audience, spiffe_id).await?;

        response
            .svids
            .into_iter()
            .map(|r| {
                let mut svid = JwtSvid::from_str(&r.svid).map_err(GrpcClientError::JwtSvid)?;
                if !r.hint.is_empty() {
                    svid = svid.with_hint(Arc::<str>::from(r.hint.as_str()));
                }
                Ok(svid)
            })
            .collect()
    }

    /// Fetches the JWT-SVID whose Workload API hint matches `hint`.
    ///
    /// This is a convenience wrapper around [`WorkloadApiClient::fetch_all_jwt_svids`] that selects
    /// a single [`JwtSvid`] by its hint.
    ///
    /// The hint is **not** part of the JWT token; it is transport metadata provided by the SPIFFE
    /// Workload API to help identify a specific SVID when multiple are available.
    ///
    /// If `spiffe_id` is `None`, the Workload API returns JWT-SVIDs for the default identity.
    ///
    /// # Errors
    ///
    /// Returns a [`GrpcClientError`] if the JWT-SVID request fails, the Workload API response is
    /// invalid, or no JWT-SVID with the requested hint is found.
    pub async fn fetch_jwt_svid_by_hint<T: AsRef<str> + ToString>(
        &mut self,
        audience: &[T],
        spiffe_id: Option<&SpiffeId>,
        hint: &str,
    ) -> Result<JwtSvid, GrpcClientError> {
        let all = self.fetch_all_jwt_svids(audience, spiffe_id).await?;
        all.into_iter()
            .find(|s| s.hint() == Some(hint))
            .ok_or(GrpcClientError::EmptyResponse)
    }

    /// Fetches a JWT-SVID token string for the given audience and optional SPIFFE ID.
    ///
    /// If `spiffe_id` is `None`, the Workload API returns the default identity.
    ///
    /// # Errors
    ///
    /// Returns a [`GrpcClientError`] if the token request fails or the Workload API
    /// returns an invalid or empty response.
    pub async fn fetch_jwt_token<T: AsRef<str> + ToString>(
        &mut self,
        audience: &[T],
        spiffe_id: Option<&SpiffeId>,
    ) -> Result<String, GrpcClientError> {
        let response = self.fetch_jwt(audience, spiffe_id).await?;
        response
            .svids
            .get(DEFAULT_SVID)
            .map(|r| r.svid.clone())
            .ok_or(GrpcClientError::EmptyResponse)
    }

    /// Validates a `JwtSvid` for the given audience and returns the parsed [`JwtSvid`].
    ///
    /// # Errors
    ///
    /// Returns a [`GrpcClientError`] if validation fails or the token cannot be parsed.
    pub async fn validate_jwt_token<T: AsRef<str> + ToString>(
        &mut self,
        audience: T,
        jwt_token: &str,
    ) -> Result<JwtSvid, GrpcClientError> {
        let _ = self.validate_jwt(audience, jwt_token).await?;
        let jwt_svid = JwtSvid::parse_insecure(jwt_token)?;
        Ok(jwt_svid)
    }

    /// Streams X.509 context updates from the Workload API.
    ///
    /// # Errors
    ///
    /// Returns a [`GrpcClientError`] if the Workload API stream cannot be
    /// established or the initial request fails.
    pub async fn stream_x509_contexts(
        &mut self,
    ) -> Result<
        impl Stream<Item = Result<X509Context, GrpcClientError>> + Send + 'static,
        GrpcClientError,
    > {
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
    ///
    /// # Errors
    ///
    /// Returns a [`GrpcClientError`] if the stream cannot be established or if a
    /// stream item fails to be received or parsed.
    pub async fn stream_x509_svids(
        &mut self,
    ) -> Result<impl Stream<Item = Result<X509Svid, GrpcClientError>> + 'static, GrpcClientError>
    {
        let request = X509svidRequest::default();
        let response = self.client.fetch_x509svid(request).await?;
        let stream = response.into_inner().map(|message| {
            message
                .map_err(GrpcClientError::from)
                .and_then(|resp| WorkloadApiClient::parse_x509_svid_from_grpc_response(&resp))
        });
        Ok(stream)
    }

    /// Streams X.509 bundle set updates from the Workload API.
    ///
    /// # Errors
    ///
    /// Returns a [`GrpcClientError`] if the Workload API stream cannot be
    /// established or the initial request fails.
    pub async fn stream_x509_bundles(
        &mut self,
    ) -> Result<impl Stream<Item = Result<X509BundleSet, GrpcClientError>> + 'static, GrpcClientError>
    {
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
    ///
    /// # Errors
    ///
    /// Returns a [`GrpcClientError`] if the Workload API stream cannot be
    /// established or the initial request fails.
    pub async fn stream_jwt_bundles(
        &mut self,
    ) -> Result<impl Stream<Item = Result<JwtBundleSet, GrpcClientError>> + 'static, GrpcClientError>
    {
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
            audience: audience.iter().map(ToString::to_string).collect(),
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
        response: &X509svidResponse,
    ) -> Result<X509Svid, GrpcClientError> {
        let svid = response
            .svids
            .get(DEFAULT_SVID)
            .ok_or(GrpcClientError::EmptyResponse)?;

        X509Svid::parse_from_der_with_hint(
            svid.x509_svid.as_ref(),
            svid.x509_svid_key.as_ref(),
            (!svid.hint.is_empty()).then(|| Arc::<str>::from(svid.hint.as_str())),
        )
        .map_err(GrpcClientError::from)
    }

    fn parse_x509_svids_from_grpc_response(
        response: &X509svidResponse,
    ) -> Result<Vec<X509Svid>, GrpcClientError> {
        response
            .svids
            .iter()
            .map(|svid| {
                let hint = (!svid.hint.is_empty()).then(|| Arc::<str>::from(svid.hint.as_str()));

                X509Svid::parse_from_der_with_hint(
                    svid.x509_svid.as_ref(),
                    svid.x509_svid_key.as_ref(),
                    hint,
                )
                .map_err(GrpcClientError::from)
            })
            .collect()
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

        for (td, bundle_data) in response.bundles {
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
        let mut svids: Vec<Arc<X509Svid>> = Vec::new();
        let mut bundle_set = X509BundleSet::new();

        for svid in response.svids {
            let hint = (!svid.hint.is_empty()).then(|| Arc::<str>::from(svid.hint.as_str()));

            let x509_svid = X509Svid::parse_from_der_with_hint(
                svid.x509_svid.as_ref(),
                svid.x509_svid_key.as_ref(),
                hint,
            )
            .map_err(GrpcClientError::from)?;

            let trust_domain = x509_svid.spiffe_id().trust_domain().clone();
            svids.push(Arc::new(x509_svid));

            let bundle = X509Bundle::parse_from_der(trust_domain, svid.bundle.as_ref())
                .map_err(GrpcClientError::from)?;
            bundle_set.add_bundle(bundle);
        }

        for (trust_domain, bundle) in response.federated_bundles {
            let trust_domain = TrustDomain::try_from(trust_domain)?;
            let x509_bundle = X509Bundle::parse_from_der(trust_domain, bundle.as_ref())
                .map_err(GrpcClientError::from)?;
            bundle_set.add_bundle(x509_bundle);
        }

        Ok(X509Context::new(svids, Arc::new(bundle_set)))
    }
}
