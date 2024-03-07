/// The X509SVIDRequest message conveys parameters for requesting an X.509-SVID.
/// There are currently no request parameters.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct X509svidRequest {}
/// The X509SVIDResponse message carries X.509-SVIDs and related information,
/// including a set of global CRLs and a list of bundles the workload may use
/// for federating with foreign trust domains.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct X509svidResponse {
    /// Required. A list of X509SVID messages, each of which includes a single
    /// X.509-SVID, its private key, and the bundle for the trust domain.
    #[prost(message, repeated, tag = "1")]
    pub svids: ::prost::alloc::vec::Vec<X509svid>,
    /// Optional. ASN.1 DER encoded certificate revocation lists.
    #[prost(bytes = "bytes", repeated, tag = "2")]
    pub crl: ::prost::alloc::vec::Vec<::prost::bytes::Bytes>,
    /// Optional. CA certificate bundles belonging to foreign trust domains that
    /// the workload should trust, keyed by the SPIFFE ID of the foreign trust
    /// domain. Bundles are ASN.1 DER encoded.
    #[prost(map = "string, bytes", tag = "3")]
    pub federated_bundles:
        ::std::collections::HashMap<::prost::alloc::string::String, ::prost::bytes::Bytes>,
}
/// The X509SVID message carries a single SVID and all associated information,
/// including the X.509 bundle for the trust domain.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct X509svid {
    /// Required. The SPIFFE ID of the SVID in this entry
    #[prost(string, tag = "1")]
    pub spiffe_id: ::prost::alloc::string::String,
    /// Required. ASN.1 DER encoded certificate chain. MAY include
    /// intermediates, the leaf certificate (or SVID itself) MUST come first.
    #[prost(bytes = "bytes", tag = "2")]
    pub x509_svid: ::prost::bytes::Bytes,
    /// Required. ASN.1 DER encoded PKCS#8 private key. MUST be unencrypted.
    #[prost(bytes = "bytes", tag = "3")]
    pub x509_svid_key: ::prost::bytes::Bytes,
    /// Required. ASN.1 DER encoded X.509 bundle for the trust domain.
    #[prost(bytes = "bytes", tag = "4")]
    pub bundle: ::prost::bytes::Bytes,
}
/// The X509BundlesRequest message conveys parameters for requesting X.509
/// bundles. There are currently no such parameters.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct X509BundlesRequest {}
/// The X509BundlesResponse message carries a set of global CRLs and a map of
/// trust bundles the workload should trust.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct X509BundlesResponse {
    /// Optional. ASN.1 DER encoded certificate revocation lists.
    #[prost(bytes = "bytes", repeated, tag = "1")]
    pub crl: ::prost::alloc::vec::Vec<::prost::bytes::Bytes>,
    /// Required. CA certificate bundles belonging to trust domains that the
    /// workload should trust, keyed by the SPIFFE ID of the trust domain.
    /// Bundles are ASN.1 DER encoded.
    #[prost(map = "string, bytes", tag = "2")]
    pub bundles: ::std::collections::HashMap<::prost::alloc::string::String, ::prost::bytes::Bytes>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct JwtsvidRequest {
    /// Required. The audience(s) the workload intends to authenticate against.
    #[prost(string, repeated, tag = "1")]
    pub audience: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    /// Optional. The requested SPIFFE ID for the JWT-SVID. If unset, all
    /// JWT-SVIDs to which the workload is entitled are requested.
    #[prost(string, tag = "2")]
    pub spiffe_id: ::prost::alloc::string::String,
}
/// The JWTSVIDResponse message conveys JWT-SVIDs.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct JwtsvidResponse {
    /// Required. The list of returned JWT-SVIDs.
    #[prost(message, repeated, tag = "1")]
    pub svids: ::prost::alloc::vec::Vec<Jwtsvid>,
}
/// The JWTSVID message carries the JWT-SVID token and associated metadata.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Jwtsvid {
    /// Required. The SPIFFE ID of the JWT-SVID.
    #[prost(string, tag = "1")]
    pub spiffe_id: ::prost::alloc::string::String,
    /// Required. Encoded JWT using JWS Compact Serialization.
    #[prost(string, tag = "2")]
    pub svid: ::prost::alloc::string::String,
}
/// The JWTBundlesRequest message conveys parameters for requesting JWT bundles.
/// There are currently no such parameters.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct JwtBundlesRequest {}
/// The JWTBundlesReponse conveys JWT bundles.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct JwtBundlesResponse {
    /// Required. JWK encoded JWT bundles, keyed by the SPIFFE ID of the trust
    /// domain.
    #[prost(map = "string, bytes", tag = "1")]
    pub bundles: ::std::collections::HashMap<::prost::alloc::string::String, ::prost::bytes::Bytes>,
}
/// The ValidateJWTSVIDRequest message conveys request parameters for
/// JWT-SVID validation.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ValidateJwtsvidRequest {
    /// Required. The audience of the validating party. The JWT-SVID must
    /// contain an audience claim which contains this value in order to
    /// succesfully validate.
    #[prost(string, tag = "1")]
    pub audience: ::prost::alloc::string::String,
    /// Required. The JWT-SVID to validate, encoded using JWS Compact
    /// Serialization.
    #[prost(string, tag = "2")]
    pub svid: ::prost::alloc::string::String,
}
/// The ValidateJWTSVIDReponse message conveys the JWT-SVID validation results.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ValidateJwtsvidResponse {
    /// Required. The SPIFFE ID of the validated JWT-SVID.
    #[prost(string, tag = "1")]
    pub spiffe_id: ::prost::alloc::string::String,
    /// Optional. Arbitrary claims contained within the payload of the validated
    /// JWT-SVID.
    #[prost(message, optional, tag = "2")]
    pub claims: ::core::option::Option<::prost_types::Struct>,
}
/// Generated client implementations.
pub mod spiffe_workload_api_client {
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
    use tonic::codegen::http::Uri;
    use tonic::codegen::*;
    #[derive(Debug, Clone)]
    pub struct SpiffeWorkloadApiClient<T> {
        inner: tonic::client::Grpc<T>,
    }
    impl<T> SpiffeWorkloadApiClient<T>
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
        ) -> SpiffeWorkloadApiClient<InterceptedService<T, F>>
        where
            F: tonic::service::Interceptor,
            T::ResponseBody: Default,
            T: tonic::codegen::Service<
                http::Request<tonic::body::BoxBody>,
                Response = http::Response<
                    <T as tonic::client::GrpcService<tonic::body::BoxBody>>::ResponseBody,
                >,
            >,
            <T as tonic::codegen::Service<http::Request<tonic::body::BoxBody>>>::Error:
                Into<StdError> + Send + Sync,
        {
            SpiffeWorkloadApiClient::new(InterceptedService::new(inner, interceptor))
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
        /// Fetch X.509-SVIDs for all SPIFFE identities the workload is entitled to,
        /// as well as related information like trust bundles and CRLs. As this
        /// information changes, subsequent messages will be streamed from the
        /// server.
        pub async fn fetch_x509svid(
            &mut self,
            request: impl tonic::IntoRequest<super::X509svidRequest>,
        ) -> std::result::Result<
            tonic::Response<tonic::codec::Streaming<super::X509svidResponse>>,
            tonic::Status,
        > {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/SpiffeWorkloadAPI/FetchX509SVID");
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(GrpcMethod::new("SpiffeWorkloadAPI", "FetchX509SVID"));
            self.inner.server_streaming(req, path, codec).await
        }
        /// Fetch trust bundles and CRLs. Useful for clients that only need to
        /// validate SVIDs without obtaining an SVID for themself. As this
        /// information changes, subsequent messages will be streamed from the
        /// server.
        pub async fn fetch_x509_bundles(
            &mut self,
            request: impl tonic::IntoRequest<super::X509BundlesRequest>,
        ) -> std::result::Result<
            tonic::Response<tonic::codec::Streaming<super::X509BundlesResponse>>,
            tonic::Status,
        > {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/SpiffeWorkloadAPI/FetchX509Bundles");
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(GrpcMethod::new("SpiffeWorkloadAPI", "FetchX509Bundles"));
            self.inner.server_streaming(req, path, codec).await
        }
        /// Fetch JWT-SVIDs for all SPIFFE identities the workload is entitled to,
        /// for the requested audience. If an optional SPIFFE ID is requested, only
        /// the JWT-SVID for that SPIFFE ID is returned.
        pub async fn fetch_jwtsvid(
            &mut self,
            request: impl tonic::IntoRequest<super::JwtsvidRequest>,
        ) -> std::result::Result<tonic::Response<super::JwtsvidResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/SpiffeWorkloadAPI/FetchJWTSVID");
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(GrpcMethod::new("SpiffeWorkloadAPI", "FetchJWTSVID"));
            self.inner.unary(req, path, codec).await
        }
        /// Fetches the JWT bundles, formatted as JWKS documents, keyed by the
        /// SPIFFE ID of the trust domain. As this information changes, subsequent
        /// messages will be streamed from the server.
        pub async fn fetch_jwt_bundles(
            &mut self,
            request: impl tonic::IntoRequest<super::JwtBundlesRequest>,
        ) -> std::result::Result<
            tonic::Response<tonic::codec::Streaming<super::JwtBundlesResponse>>,
            tonic::Status,
        > {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/SpiffeWorkloadAPI/FetchJWTBundles");
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(GrpcMethod::new("SpiffeWorkloadAPI", "FetchJWTBundles"));
            self.inner.server_streaming(req, path, codec).await
        }
        /// Validates a JWT-SVID against the requested audience. Returns the SPIFFE
        /// ID of the JWT-SVID and JWT claims.
        pub async fn validate_jwtsvid(
            &mut self,
            request: impl tonic::IntoRequest<super::ValidateJwtsvidRequest>,
        ) -> std::result::Result<tonic::Response<super::ValidateJwtsvidResponse>, tonic::Status>
        {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/SpiffeWorkloadAPI/ValidateJWTSVID");
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(GrpcMethod::new("SpiffeWorkloadAPI", "ValidateJWTSVID"));
            self.inner.unary(req, path, codec).await
        }
    }
}
/// Generated server implementations.
pub mod spiffe_workload_api_server {
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
    use tonic::codegen::*;
    /// Generated trait containing gRPC methods that should be implemented for use with SpiffeWorkloadApiServer.
    #[async_trait]
    pub trait SpiffeWorkloadApi: Send + Sync + 'static {
        /// Server streaming response type for the FetchX509SVID method.
        type FetchX509SVIDStream: tonic::codegen::tokio_stream::Stream<
                Item = std::result::Result<super::X509svidResponse, tonic::Status>,
            > + Send
            + 'static;
        /// Fetch X.509-SVIDs for all SPIFFE identities the workload is entitled to,
        /// as well as related information like trust bundles and CRLs. As this
        /// information changes, subsequent messages will be streamed from the
        /// server.
        async fn fetch_x509svid(
            &self,
            request: tonic::Request<super::X509svidRequest>,
        ) -> std::result::Result<tonic::Response<Self::FetchX509SVIDStream>, tonic::Status>;
        /// Server streaming response type for the FetchX509Bundles method.
        type FetchX509BundlesStream: tonic::codegen::tokio_stream::Stream<
                Item = std::result::Result<super::X509BundlesResponse, tonic::Status>,
            > + Send
            + 'static;
        /// Fetch trust bundles and CRLs. Useful for clients that only need to
        /// validate SVIDs without obtaining an SVID for themself. As this
        /// information changes, subsequent messages will be streamed from the
        /// server.
        async fn fetch_x509_bundles(
            &self,
            request: tonic::Request<super::X509BundlesRequest>,
        ) -> std::result::Result<tonic::Response<Self::FetchX509BundlesStream>, tonic::Status>;
        /// Fetch JWT-SVIDs for all SPIFFE identities the workload is entitled to,
        /// for the requested audience. If an optional SPIFFE ID is requested, only
        /// the JWT-SVID for that SPIFFE ID is returned.
        async fn fetch_jwtsvid(
            &self,
            request: tonic::Request<super::JwtsvidRequest>,
        ) -> std::result::Result<tonic::Response<super::JwtsvidResponse>, tonic::Status>;
        /// Server streaming response type for the FetchJWTBundles method.
        type FetchJWTBundlesStream: tonic::codegen::tokio_stream::Stream<
                Item = std::result::Result<super::JwtBundlesResponse, tonic::Status>,
            > + Send
            + 'static;
        /// Fetches the JWT bundles, formatted as JWKS documents, keyed by the
        /// SPIFFE ID of the trust domain. As this information changes, subsequent
        /// messages will be streamed from the server.
        async fn fetch_jwt_bundles(
            &self,
            request: tonic::Request<super::JwtBundlesRequest>,
        ) -> std::result::Result<tonic::Response<Self::FetchJWTBundlesStream>, tonic::Status>;
        /// Validates a JWT-SVID against the requested audience. Returns the SPIFFE
        /// ID of the JWT-SVID and JWT claims.
        async fn validate_jwtsvid(
            &self,
            request: tonic::Request<super::ValidateJwtsvidRequest>,
        ) -> std::result::Result<tonic::Response<super::ValidateJwtsvidResponse>, tonic::Status>;
    }
    #[derive(Debug)]
    pub struct SpiffeWorkloadApiServer<T: SpiffeWorkloadApi> {
        inner: _Inner<T>,
        accept_compression_encodings: EnabledCompressionEncodings,
        send_compression_encodings: EnabledCompressionEncodings,
        max_decoding_message_size: Option<usize>,
        max_encoding_message_size: Option<usize>,
    }
    struct _Inner<T>(Arc<T>);
    impl<T: SpiffeWorkloadApi> SpiffeWorkloadApiServer<T> {
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
        pub fn with_interceptor<F>(inner: T, interceptor: F) -> InterceptedService<Self, F>
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
    impl<T, B> tonic::codegen::Service<http::Request<B>> for SpiffeWorkloadApiServer<T>
    where
        T: SpiffeWorkloadApi,
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
                "/SpiffeWorkloadAPI/FetchX509SVID" => {
                    #[allow(non_camel_case_types)]
                    struct FetchX509SVIDSvc<T: SpiffeWorkloadApi>(pub Arc<T>);
                    impl<T: SpiffeWorkloadApi>
                        tonic::server::ServerStreamingService<super::X509svidRequest>
                        for FetchX509SVIDSvc<T>
                    {
                        type Response = super::X509svidResponse;
                        type ResponseStream = T::FetchX509SVIDStream;
                        type Future =
                            BoxFuture<tonic::Response<Self::ResponseStream>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::X509svidRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as SpiffeWorkloadApi>::fetch_x509svid(&inner, request).await
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
                        let method = FetchX509SVIDSvc(inner);
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
                "/SpiffeWorkloadAPI/FetchX509Bundles" => {
                    #[allow(non_camel_case_types)]
                    struct FetchX509BundlesSvc<T: SpiffeWorkloadApi>(pub Arc<T>);
                    impl<T: SpiffeWorkloadApi>
                        tonic::server::ServerStreamingService<super::X509BundlesRequest>
                        for FetchX509BundlesSvc<T>
                    {
                        type Response = super::X509BundlesResponse;
                        type ResponseStream = T::FetchX509BundlesStream;
                        type Future =
                            BoxFuture<tonic::Response<Self::ResponseStream>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::X509BundlesRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as SpiffeWorkloadApi>::fetch_x509_bundles(&inner, request).await
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
                        let method = FetchX509BundlesSvc(inner);
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
                "/SpiffeWorkloadAPI/FetchJWTSVID" => {
                    #[allow(non_camel_case_types)]
                    struct FetchJWTSVIDSvc<T: SpiffeWorkloadApi>(pub Arc<T>);
                    impl<T: SpiffeWorkloadApi> tonic::server::UnaryService<super::JwtsvidRequest>
                        for FetchJWTSVIDSvc<T>
                    {
                        type Response = super::JwtsvidResponse;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::JwtsvidRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as SpiffeWorkloadApi>::fetch_jwtsvid(&inner, request).await
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
                        let method = FetchJWTSVIDSvc(inner);
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
                "/SpiffeWorkloadAPI/FetchJWTBundles" => {
                    #[allow(non_camel_case_types)]
                    struct FetchJWTBundlesSvc<T: SpiffeWorkloadApi>(pub Arc<T>);
                    impl<T: SpiffeWorkloadApi>
                        tonic::server::ServerStreamingService<super::JwtBundlesRequest>
                        for FetchJWTBundlesSvc<T>
                    {
                        type Response = super::JwtBundlesResponse;
                        type ResponseStream = T::FetchJWTBundlesStream;
                        type Future =
                            BoxFuture<tonic::Response<Self::ResponseStream>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::JwtBundlesRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as SpiffeWorkloadApi>::fetch_jwt_bundles(&inner, request).await
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
                        let method = FetchJWTBundlesSvc(inner);
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
                "/SpiffeWorkloadAPI/ValidateJWTSVID" => {
                    #[allow(non_camel_case_types)]
                    struct ValidateJWTSVIDSvc<T: SpiffeWorkloadApi>(pub Arc<T>);
                    impl<T: SpiffeWorkloadApi>
                        tonic::server::UnaryService<super::ValidateJwtsvidRequest>
                        for ValidateJWTSVIDSvc<T>
                    {
                        type Response = super::ValidateJwtsvidResponse;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::ValidateJwtsvidRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as SpiffeWorkloadApi>::validate_jwtsvid(&inner, request).await
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
                        let method = ValidateJWTSVIDSvc(inner);
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
                _ => Box::pin(async move {
                    Ok(http::Response::builder()
                        .status(200)
                        .header("grpc-status", "12")
                        .header("content-type", "application/grpc")
                        .body(empty_body())
                        .unwrap())
                }),
            }
        }
    }
    impl<T: SpiffeWorkloadApi> Clone for SpiffeWorkloadApiServer<T> {
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
    impl<T: SpiffeWorkloadApi> Clone for _Inner<T> {
        fn clone(&self) -> Self {
            Self(Arc::clone(&self.0))
        }
    }
    impl<T: std::fmt::Debug> std::fmt::Debug for _Inner<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{:?}", self.0)
        }
    }
    impl<T: SpiffeWorkloadApi> tonic::server::NamedService for SpiffeWorkloadApiServer<T> {
        const NAME: &'static str = "SpiffeWorkloadAPI";
    }
}
