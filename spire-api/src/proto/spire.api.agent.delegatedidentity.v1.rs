/// X.509 SPIFFE Verifiable Identity Document with the private key.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct X509svidWithKey {
    /// The workload X509-SVID.
    #[prost(message, optional, tag = "1")]
    pub x509_svid: ::core::option::Option<super::super::super::types::X509svid>,
    /// Private key (encoding DER PKCS#8).
    #[prost(bytes = "bytes", tag = "2")]
    pub x509_svid_key: ::prost::bytes::Bytes,
}
/// SubscribeToX509SVIDsRequest is used by clients to subscribe the set of SVIDs that
/// any given workload is entitled to. Clients subscribe to a workload's SVIDs by providing
/// a set of selectors describing the workload.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SubscribeToX509sviDsRequest {
    /// Required. Selectors describing the workload to subscribe to.
    #[prost(message, repeated, tag = "1")]
    pub selectors: ::prost::alloc::vec::Vec<super::super::super::types::Selector>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SubscribeToX509sviDsResponse {
    #[prost(message, repeated, tag = "1")]
    pub x509_svids: ::prost::alloc::vec::Vec<X509svidWithKey>,
    /// Names of the trust domains that this workload should federates with.
    #[prost(string, repeated, tag = "2")]
    pub federates_with: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SubscribeToX509BundlesRequest {}
/// SubscribeToX509BundlesResponse contains all bundles that the agent is tracking,
/// including the local bundle. When an update occurs, or bundles are added or removed,
/// a new response with the full set of bundles is sent.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SubscribeToX509BundlesResponse {
    /// A map keyed by trust domain name, with ASN.1 DER-encoded
    /// X.509 CA certificates as the values
    #[prost(map = "string, bytes", tag = "1")]
    pub ca_certificates: ::std::collections::HashMap<
        ::prost::alloc::string::String,
        ::prost::bytes::Bytes,
    >,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FetchJwtsviDsRequest {
    /// Required. The audience(s) the workload intends to authenticate against.
    #[prost(string, repeated, tag = "1")]
    pub audience: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    /// Required. Selectors describing the workload to fetch.
    #[prost(message, repeated, tag = "2")]
    pub selectors: ::prost::alloc::vec::Vec<super::super::super::types::Selector>,
}
/// The FetchJWTSVIDsResponse message conveys JWT-SVIDs.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FetchJwtsviDsResponse {
    /// Required. The list of returned JWT-SVIDs.
    #[prost(message, repeated, tag = "1")]
    pub svids: ::prost::alloc::vec::Vec<super::super::super::types::Jwtsvid>,
}
/// The SubscribeToJWTBundlesRequest message conveys parameters for requesting JWKS bundles.
/// There are currently no such parameters.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SubscribeToJwtBundlesRequest {}
/// The SubscribeToJWTBundlesReponse conveys JWKS bundles.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SubscribeToJwtBundlesResponse {
    /// Required. JWK encoded JWT bundles, keyed by the SPIFFE ID of the trust
    /// domain.
    #[prost(map = "string, bytes", tag = "1")]
    pub bundles: ::std::collections::HashMap<
        ::prost::alloc::string::String,
        ::prost::bytes::Bytes,
    >,
}
/// Generated client implementations.
pub mod delegated_identity_client {
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
    use tonic::codegen::*;
    use tonic::codegen::http::Uri;
    /// The delegatedIdentity service provides an interface to get the SVIDs of other
    /// workloads on the host. This service is intended for use cases where a process
    /// (different than the workload one) should access the workload's SVID to
    /// perform actions on behalf of the workload. One example of is using a single
    /// node instance of Envoy that upgrades TCP connections for different processes
    /// running in such a node.
    ///
    /// The caller must be local and its identity must be listed in the allowed
    /// clients on the spire-agent configuration.
    #[derive(Debug, Clone)]
    pub struct DelegatedIdentityClient<T> {
        inner: tonic::client::Grpc<T>,
    }
    impl<T> DelegatedIdentityClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::BoxBody>,
        T::Error: Into<StdError>,
        T::ResponseBody: Body<Data = Bytes> + Send + 'static,
        <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }
        pub fn with_origin(inner: T, origin: Uri) -> Self {
            let inner = tonic::client::Grpc::with_origin(inner, origin);
            Self { inner }
        }
        pub fn with_interceptor<F>(
            inner: T,
            interceptor: F,
        ) -> DelegatedIdentityClient<InterceptedService<T, F>>
        where
            F: tonic::service::Interceptor,
            T::ResponseBody: Default,
            T: tonic::codegen::Service<
                http::Request<tonic::body::BoxBody>,
                Response = http::Response<
                    <T as tonic::client::GrpcService<tonic::body::BoxBody>>::ResponseBody,
                >,
            >,
            <T as tonic::codegen::Service<
                http::Request<tonic::body::BoxBody>,
            >>::Error: Into<StdError> + Send + Sync,
        {
            DelegatedIdentityClient::new(InterceptedService::new(inner, interceptor))
        }
        /// Compress requests with the given encoding.
        ///
        /// This requires the server to support it otherwise it might respond with an
        /// error.
        #[must_use]
        pub fn send_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.inner = self.inner.send_compressed(encoding);
            self
        }
        /// Enable decompressing responses.
        #[must_use]
        pub fn accept_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.inner = self.inner.accept_compressed(encoding);
            self
        }
        /// Limits the maximum size of a decoded message.
        ///
        /// Default: `4MB`
        #[must_use]
        pub fn max_decoding_message_size(mut self, limit: usize) -> Self {
            self.inner = self.inner.max_decoding_message_size(limit);
            self
        }
        /// Limits the maximum size of an encoded message.
        ///
        /// Default: `usize::MAX`
        #[must_use]
        pub fn max_encoding_message_size(mut self, limit: usize) -> Self {
            self.inner = self.inner.max_encoding_message_size(limit);
            self
        }
        /// Subscribe to get X.509-SVIDs for workloads that match the given selectors.
        /// The lifetime of the subscription aligns to the lifetime of the stream.
        pub async fn subscribe_to_x509svi_ds(
            &mut self,
            request: impl tonic::IntoRequest<super::SubscribeToX509sviDsRequest>,
        ) -> std::result::Result<
            tonic::Response<
                tonic::codec::Streaming<super::SubscribeToX509sviDsResponse>,
            >,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/spire.api.agent.delegatedidentity.v1.DelegatedIdentity/SubscribeToX509SVIDs",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "spire.api.agent.delegatedidentity.v1.DelegatedIdentity",
                        "SubscribeToX509SVIDs",
                    ),
                );
            self.inner.server_streaming(req, path, codec).await
        }
        /// Subscribe to get local and all federated bundles.
        /// The lifetime of the subscription aligns to the lifetime of the stream.
        pub async fn subscribe_to_x509_bundles(
            &mut self,
            request: impl tonic::IntoRequest<super::SubscribeToX509BundlesRequest>,
        ) -> std::result::Result<
            tonic::Response<
                tonic::codec::Streaming<super::SubscribeToX509BundlesResponse>,
            >,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/spire.api.agent.delegatedidentity.v1.DelegatedIdentity/SubscribeToX509Bundles",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "spire.api.agent.delegatedidentity.v1.DelegatedIdentity",
                        "SubscribeToX509Bundles",
                    ),
                );
            self.inner.server_streaming(req, path, codec).await
        }
        /// Fetch JWT-SVIDs for workloads that match the given selectors, and
        /// for the requested audience.
        pub async fn fetch_jwtsvi_ds(
            &mut self,
            request: impl tonic::IntoRequest<super::FetchJwtsviDsRequest>,
        ) -> std::result::Result<
            tonic::Response<super::FetchJwtsviDsResponse>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/spire.api.agent.delegatedidentity.v1.DelegatedIdentity/FetchJWTSVIDs",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "spire.api.agent.delegatedidentity.v1.DelegatedIdentity",
                        "FetchJWTSVIDs",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        /// Subscribe to get local and all federated JWKS bundles.
        /// The lifetime of the subscription aligns to the lifetime of the stream.
        pub async fn subscribe_to_jwt_bundles(
            &mut self,
            request: impl tonic::IntoRequest<super::SubscribeToJwtBundlesRequest>,
        ) -> std::result::Result<
            tonic::Response<
                tonic::codec::Streaming<super::SubscribeToJwtBundlesResponse>,
            >,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/spire.api.agent.delegatedidentity.v1.DelegatedIdentity/SubscribeToJWTBundles",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "spire.api.agent.delegatedidentity.v1.DelegatedIdentity",
                        "SubscribeToJWTBundles",
                    ),
                );
            self.inner.server_streaming(req, path, codec).await
        }
    }
}
/// Generated server implementations.
pub mod delegated_identity_server {
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
    use tonic::codegen::*;
    /// Generated trait containing gRPC methods that should be implemented for use with DelegatedIdentityServer.
    #[async_trait]
    pub trait DelegatedIdentity: Send + Sync + 'static {
        /// Server streaming response type for the SubscribeToX509SVIDs method.
        type SubscribeToX509SVIDsStream: tonic::codegen::tokio_stream::Stream<
                Item = std::result::Result<
                    super::SubscribeToX509sviDsResponse,
                    tonic::Status,
                >,
            >
            + Send
            + 'static;
        /// Subscribe to get X.509-SVIDs for workloads that match the given selectors.
        /// The lifetime of the subscription aligns to the lifetime of the stream.
        async fn subscribe_to_x509svi_ds(
            &self,
            request: tonic::Request<super::SubscribeToX509sviDsRequest>,
        ) -> std::result::Result<
            tonic::Response<Self::SubscribeToX509SVIDsStream>,
            tonic::Status,
        >;
        /// Server streaming response type for the SubscribeToX509Bundles method.
        type SubscribeToX509BundlesStream: tonic::codegen::tokio_stream::Stream<
                Item = std::result::Result<
                    super::SubscribeToX509BundlesResponse,
                    tonic::Status,
                >,
            >
            + Send
            + 'static;
        /// Subscribe to get local and all federated bundles.
        /// The lifetime of the subscription aligns to the lifetime of the stream.
        async fn subscribe_to_x509_bundles(
            &self,
            request: tonic::Request<super::SubscribeToX509BundlesRequest>,
        ) -> std::result::Result<
            tonic::Response<Self::SubscribeToX509BundlesStream>,
            tonic::Status,
        >;
        /// Fetch JWT-SVIDs for workloads that match the given selectors, and
        /// for the requested audience.
        async fn fetch_jwtsvi_ds(
            &self,
            request: tonic::Request<super::FetchJwtsviDsRequest>,
        ) -> std::result::Result<
            tonic::Response<super::FetchJwtsviDsResponse>,
            tonic::Status,
        >;
        /// Server streaming response type for the SubscribeToJWTBundles method.
        type SubscribeToJWTBundlesStream: tonic::codegen::tokio_stream::Stream<
                Item = std::result::Result<
                    super::SubscribeToJwtBundlesResponse,
                    tonic::Status,
                >,
            >
            + Send
            + 'static;
        /// Subscribe to get local and all federated JWKS bundles.
        /// The lifetime of the subscription aligns to the lifetime of the stream.
        async fn subscribe_to_jwt_bundles(
            &self,
            request: tonic::Request<super::SubscribeToJwtBundlesRequest>,
        ) -> std::result::Result<
            tonic::Response<Self::SubscribeToJWTBundlesStream>,
            tonic::Status,
        >;
    }
    /// The delegatedIdentity service provides an interface to get the SVIDs of other
    /// workloads on the host. This service is intended for use cases where a process
    /// (different than the workload one) should access the workload's SVID to
    /// perform actions on behalf of the workload. One example of is using a single
    /// node instance of Envoy that upgrades TCP connections for different processes
    /// running in such a node.
    ///
    /// The caller must be local and its identity must be listed in the allowed
    /// clients on the spire-agent configuration.
    #[derive(Debug)]
    pub struct DelegatedIdentityServer<T: DelegatedIdentity> {
        inner: _Inner<T>,
        accept_compression_encodings: EnabledCompressionEncodings,
        send_compression_encodings: EnabledCompressionEncodings,
        max_decoding_message_size: Option<usize>,
        max_encoding_message_size: Option<usize>,
    }
    struct _Inner<T>(Arc<T>);
    impl<T: DelegatedIdentity> DelegatedIdentityServer<T> {
        pub fn new(inner: T) -> Self {
            Self::from_arc(Arc::new(inner))
        }
        pub fn from_arc(inner: Arc<T>) -> Self {
            let inner = _Inner(inner);
            Self {
                inner,
                accept_compression_encodings: Default::default(),
                send_compression_encodings: Default::default(),
                max_decoding_message_size: None,
                max_encoding_message_size: None,
            }
        }
        pub fn with_interceptor<F>(
            inner: T,
            interceptor: F,
        ) -> InterceptedService<Self, F>
        where
            F: tonic::service::Interceptor,
        {
            InterceptedService::new(Self::new(inner), interceptor)
        }
        /// Enable decompressing requests with the given encoding.
        #[must_use]
        pub fn accept_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.accept_compression_encodings.enable(encoding);
            self
        }
        /// Compress responses with the given encoding, if the client supports it.
        #[must_use]
        pub fn send_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.send_compression_encodings.enable(encoding);
            self
        }
        /// Limits the maximum size of a decoded message.
        ///
        /// Default: `4MB`
        #[must_use]
        pub fn max_decoding_message_size(mut self, limit: usize) -> Self {
            self.max_decoding_message_size = Some(limit);
            self
        }
        /// Limits the maximum size of an encoded message.
        ///
        /// Default: `usize::MAX`
        #[must_use]
        pub fn max_encoding_message_size(mut self, limit: usize) -> Self {
            self.max_encoding_message_size = Some(limit);
            self
        }
    }
    impl<T, B> tonic::codegen::Service<http::Request<B>> for DelegatedIdentityServer<T>
    where
        T: DelegatedIdentity,
        B: Body + Send + 'static,
        B::Error: Into<StdError> + Send + 'static,
    {
        type Response = http::Response<tonic::body::BoxBody>;
        type Error = std::convert::Infallible;
        type Future = BoxFuture<Self::Response, Self::Error>;
        fn poll_ready(
            &mut self,
            _cx: &mut Context<'_>,
        ) -> Poll<std::result::Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
        fn call(&mut self, req: http::Request<B>) -> Self::Future {
            let inner = self.inner.clone();
            match req.uri().path() {
                "/spire.api.agent.delegatedidentity.v1.DelegatedIdentity/SubscribeToX509SVIDs" => {
                    #[allow(non_camel_case_types)]
                    struct SubscribeToX509SVIDsSvc<T: DelegatedIdentity>(pub Arc<T>);
                    impl<
                        T: DelegatedIdentity,
                    > tonic::server::ServerStreamingService<
                        super::SubscribeToX509sviDsRequest,
                    > for SubscribeToX509SVIDsSvc<T> {
                        type Response = super::SubscribeToX509sviDsResponse;
                        type ResponseStream = T::SubscribeToX509SVIDsStream;
                        type Future = BoxFuture<
                            tonic::Response<Self::ResponseStream>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::SubscribeToX509sviDsRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as DelegatedIdentity>::subscribe_to_x509svi_ds(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = SubscribeToX509SVIDsSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.server_streaming(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/spire.api.agent.delegatedidentity.v1.DelegatedIdentity/SubscribeToX509Bundles" => {
                    #[allow(non_camel_case_types)]
                    struct SubscribeToX509BundlesSvc<T: DelegatedIdentity>(pub Arc<T>);
                    impl<
                        T: DelegatedIdentity,
                    > tonic::server::ServerStreamingService<
                        super::SubscribeToX509BundlesRequest,
                    > for SubscribeToX509BundlesSvc<T> {
                        type Response = super::SubscribeToX509BundlesResponse;
                        type ResponseStream = T::SubscribeToX509BundlesStream;
                        type Future = BoxFuture<
                            tonic::Response<Self::ResponseStream>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::SubscribeToX509BundlesRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as DelegatedIdentity>::subscribe_to_x509_bundles(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = SubscribeToX509BundlesSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.server_streaming(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/spire.api.agent.delegatedidentity.v1.DelegatedIdentity/FetchJWTSVIDs" => {
                    #[allow(non_camel_case_types)]
                    struct FetchJWTSVIDsSvc<T: DelegatedIdentity>(pub Arc<T>);
                    impl<
                        T: DelegatedIdentity,
                    > tonic::server::UnaryService<super::FetchJwtsviDsRequest>
                    for FetchJWTSVIDsSvc<T> {
                        type Response = super::FetchJwtsviDsResponse;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::FetchJwtsviDsRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as DelegatedIdentity>::fetch_jwtsvi_ds(&inner, request)
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = FetchJWTSVIDsSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/spire.api.agent.delegatedidentity.v1.DelegatedIdentity/SubscribeToJWTBundles" => {
                    #[allow(non_camel_case_types)]
                    struct SubscribeToJWTBundlesSvc<T: DelegatedIdentity>(pub Arc<T>);
                    impl<
                        T: DelegatedIdentity,
                    > tonic::server::ServerStreamingService<
                        super::SubscribeToJwtBundlesRequest,
                    > for SubscribeToJWTBundlesSvc<T> {
                        type Response = super::SubscribeToJwtBundlesResponse;
                        type ResponseStream = T::SubscribeToJWTBundlesStream;
                        type Future = BoxFuture<
                            tonic::Response<Self::ResponseStream>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::SubscribeToJwtBundlesRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as DelegatedIdentity>::subscribe_to_jwt_bundles(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = SubscribeToJWTBundlesSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.server_streaming(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                _ => {
                    Box::pin(async move {
                        Ok(
                            http::Response::builder()
                                .status(200)
                                .header("grpc-status", "12")
                                .header("content-type", "application/grpc")
                                .body(empty_body())
                                .unwrap(),
                        )
                    })
                }
            }
        }
    }
    impl<T: DelegatedIdentity> Clone for DelegatedIdentityServer<T> {
        fn clone(&self) -> Self {
            let inner = self.inner.clone();
            Self {
                inner,
                accept_compression_encodings: self.accept_compression_encodings,
                send_compression_encodings: self.send_compression_encodings,
                max_decoding_message_size: self.max_decoding_message_size,
                max_encoding_message_size: self.max_encoding_message_size,
            }
        }
    }
    impl<T: DelegatedIdentity> Clone for _Inner<T> {
        fn clone(&self) -> Self {
            Self(Arc::clone(&self.0))
        }
    }
    impl<T: std::fmt::Debug> std::fmt::Debug for _Inner<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{:?}", self.0)
        }
    }
    impl<T: DelegatedIdentity> tonic::server::NamedService
    for DelegatedIdentityServer<T> {
        const NAME: &'static str = "spire.api.agent.delegatedidentity.v1.DelegatedIdentity";
    }
}
